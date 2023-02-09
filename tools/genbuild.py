#!/usr/bin/python

import argparse, glob, os, sys, types
import xml.etree.ElementTree as ET

well_known_tags = { "darwin", "linux", "windows" }

def rglob(rootdir, pattern):
    return glob.iglob(os.path.join(rootdir, pattern), recursive=True)

def execfile(path):
    n = os.path.splitext(os.path.basename(path))[0]
    m = types.ModuleType(n)
    m.__file__ = path
    m.__loader__ = None
    m.__package__ = ""
    with open(path) as source:
        exec(compile(source.read(), path, "exec"), m.__dict__)
    return m

def matchtag(tags, path):
    b = os.path.splitext(os.path.basename(path))[0]
    i = b.rfind("_")
    return 0 > i or b[i + 1:] not in well_known_tags or b[i + 1:] in tags

def getfiles(tags, filespec, projdir, pathsep):
    fileset = set()
    if filespec:
        altpathsep = "\\" if pathsep == "/" else "/"
        for pattern in filespec:
            if not pattern.startswith("!"):
                op = fileset.add
            else:
                op = fileset.remove
                pattern = pattern[1:]
            if pattern == glob.escape(pattern):
                # if the pattern does not contain special characters, do not glob or match tags
                op(os.path.normpath(pattern).replace(altpathsep, pathsep))
            else:
                # if the pattern contains special characters, glob and match tags
                for f in rglob(projdir, pattern):
                    if not matchtag(tags, f):
                        continue
                    op(os.path.normpath(os.path.relpath(f, projdir)).replace(altpathsep, pathsep))
    return fileset

def xmlprettify(elem, indent="  ", level=0):
    # works for complex content only
    prev = elem
    for child in elem:
        if prev == elem:
            elem.text = "\n" + indent * (level + 1)
        else:
            prev.tail = "\n" + indent * (level + 1)
        prev = child
        xmlprettify(child, indent, level + 1)
    elem.tail = "\n" + indent * (level - 1)

def setelements(root, tag, files):
    for i in root.findall("{*}ItemGroup[{*}%s]" % tag):
        for j in i.findall("{*}%s" % tag):
            i.remove(j)
        for f in sorted(files):
            j = ET.SubElement(i, tag)
            j.set("Include", f)

def generate_vcxproj(bluedict, projfile):
    ET.register_namespace("", "http://schemas.microsoft.com/developer/msbuild/2003")
    tree = ET.parse(projfile)
    root = tree.getroot()
    tags = { "windows" }
    for i in root.findall("{*}PropertyGroup/{*}ApplicationType"):
        if "Linux" == i.text:
            tags = { "linux" }
    srcfiles = getfiles(tags, bluedict.get("Compile"), os.path.dirname(projfile), "\\")
    incfiles = getfiles(tags, bluedict.get("Include"), os.path.dirname(projfile), "\\")
    reffiles = getfiles(tags, bluedict.get("Refer"), os.path.dirname(projfile), "\\")
    setelements(root, "ClInclude", incfiles)
    setelements(root, "ClCompile", srcfiles)
    setelements(root, "None", reffiles)
    roottail = root.tail # preserve tail at end of file
    xmlprettify(root)
    root.tail = roottail
    with open(projfile, "wt", encoding="utf-8", newline="\r\n") as outfile:
        outfile.write('<?xml version="1.0" encoding="utf-8"?>\n')
        tree.write(outfile, encoding="unicode")

def iterate_lines_with_continuation(iter):
    accum = []
    for line in iter:
        if line.endswith("\\\n"):
            accum.append(line[:-2])
        elif accum:
            accum.append(line)
            yield " ".join(accum)
            accum = []
        else:
            yield line
    if accum:
        yield " ".join(accum)

def generate_mk(bluedict, projfile):
    tags = { "linux" }
    srcfiles = getfiles(tags, bluedict.get("Compile"), os.path.dirname(projfile), "/")
    incfiles = getfiles(tags, bluedict.get("Include"), os.path.dirname(projfile), "/")
    text = []
    with open(projfile, "rt", encoding="utf-8") as file:
        for line in iterate_lines_with_continuation(file):
            trline = line.translate(str.maketrans("", "", " \t\r\n"))
            if trline.startswith("Compile="):
                text.append("Compile =")
                for f in sorted(srcfiles):
                    text.append(" \\\n\t" + f)
                text.append("\n")
            elif trline.startswith("Include="):
                text.append("Include =")
                for f in sorted(incfiles):
                    text.append(" \\\n\t" + f)
                text.append("\n")
            else:
                text.append(line)
    with open(projfile, "wt", encoding="utf-8", newline="\n") as outfile:
        outfile.write("".join(text))

_genmap = {
    ".vcxproj": generate_vcxproj,
    ".mk": generate_mk,
}

def generate(bluedir, projdir):
    bluefiles = {}
    projfiles = {}
    for bluefile in rglob(bluedir, "**/*.blu"):
        k = os.path.splitext(os.path.basename(bluefile))[0]
        v = os.path.normpath(bluefile)
        bluefiles.setdefault(k, []).append(v)
    for ext in _genmap:
        for projfile in rglob(projdir, "**/*%s" % ext):
            k = os.path.splitext(os.path.basename(projfile))[0]
            v = os.path.normpath(projfile)
            projfiles.setdefault(k, []).append(v)
    for k in bluefiles:
        if 1 < len(bluefiles[k]):
            warn("%s: multiple blueprints; ignoring" % k)
            continue
        bluefile = bluefiles[k][0]
        m = execfile(bluefile)
        for projfile in projfiles.get(k, []):
            info("%s -> %s" % (bluefile, projfile))
            _genmap[os.path.splitext(projfile)[1]](m.__dict__, projfile)

def guess(projdir):
    if projdir:
        return projdir
    if sys.platform.startswith("win32"):
        projdir = "VStudio"
    elif sys.platform.startswith("linux"):
        projdir = "Linux"
    return [os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), "..", "build", projdir))]

def main():
    p = argparse.ArgumentParser()
    p.add_argument("bluedir", help="blueprint directory")
    p.add_argument("projdirs", metavar="projdir", nargs="*", help="project directory")
    args = p.parse_args(sys.argv[1:])
    for projdir in guess(args.projdirs):
        generate(args.bluedir, projdir)

def info(s):
    print("%s: %s" % (os.path.basename(sys.argv[0]), s))
def warn(s):
    print("%s: %s" % (os.path.basename(sys.argv[0]), s), file=sys.stderr)
def fail(s, exitcode = 1):
    warn(s)
    sys.exit(exitcode)

def __entry():
    try:
        main()
    except EnvironmentError as ex:
        fail(ex)
    except KeyboardInterrupt:
        fail("interrupted", 130)

if "__main__" == __name__:
    sys.dont_write_bytecode = True
    __entry()
