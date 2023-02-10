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

def tagparse_c(path):
    with open(path, "rt", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if line.startswith("//:build "):
                yield line.split()[1:]
            elif line and not line.startswith("//"):
                break

def tagparse_unknown(path):
    return []

_tagparsemap = {
    ".h": tagparse_c,
    ".hpp": tagparse_c,
    ".hxx": tagparse_c,
    ".c": tagparse_c,
    ".cpp": tagparse_c,
    ".cxx": tagparse_c,
}

def matchtag(requested_tags, is_wildcard, path):
    #
    # Consider :build lines as follows:
    #
    #     //:build TAG_1_1 TAG_1_2 ...
    #     //:build TAG_2_1 TAG_2_2 ...
    #     ...
    #     //:build TAG_n_1 TAG_n_2 ...
    #
    # A :build line is considered "satisfied" (TRUE) if the set of its tags is a subset
    # of the requested tags (i.e. all of its tags are satisfied).
    #
    #    { TAG_i_1, TAG_i_2, ... } ⊆ requested_tags
    #
    # If any :build line is satisfied then the file is included in the build. The absense
    # of :build lines also means that the file is included in the build.
    #
    # The above :build lines are equivalent to the following boolean expression:
    #
    #     (TAG_1_1 && TAG_1_2 && ...) ||
    #     (TAG_2_1 && TAG_2_2 && ...) ||
    #     ...
    #     (TAG_n_1 && TAG_n_2 && ...)
    #
    # This is inspired but different from Golang's +build constraints.
    #
    b, ext = os.path.splitext(os.path.basename(path))
    if is_wildcard:
        i = b.rfind("_")
        if 0 <= i and b[i + 1:] in well_known_tags and not b[i + 1:] in requested_tags:
            return False
    has_build_line = False
    for build_line in _tagparsemap.get(ext, tagparse_unknown)(path):
        has_build_line = True
        if set(build_line) <= requested_tags:
            return True
    return not has_build_line

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
            # only consider well known suffixes as tags when pattern is wildcard
            is_wildcard = pattern != glob.escape(pattern)
            for path in rglob(projdir, pattern):
                if not matchtag(tags, is_wildcard, path):
                    continue
                op(os.path.normpath(os.path.relpath(path, projdir)).replace(altpathsep, pathsep))
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
    tags = { "windows" }
    tags.update(bluedict.get("Tags", []))
    ET.register_namespace("", "http://schemas.microsoft.com/developer/msbuild/2003")
    tree = ET.parse(projfile)
    root = tree.getroot()
    for i in root.findall("{*}PropertyGroup/{*}ApplicationType"):
        if "Linux" == i.text:
            tags.remove("windows")
            tags.add("linux")
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
    tags.update(bluedict.get("Tags", []))
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

def main():
    builddir = os.path.relpath(os.path.join(os.path.dirname(sys.argv[0]), "..", "build"), os.getcwd())
    p = argparse.ArgumentParser()
    p.add_argument("bluedir", nargs="?", help="blueprint directory",
        default=os.path.join(builddir, "Blueprints"))
    p.add_argument("projdirs", metavar="projdir", nargs="*", help="project directory",
        default=[os.path.join(builddir, n) for n in ["VStudio", "Linux"]])
    args = p.parse_args(sys.argv[1:])
    for projdir in args.projdirs:
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
