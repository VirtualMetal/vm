#!/usr/bin/python

import argparse, glob, os, re, subprocess, sys

_indent = "  "
_colormap = {
    "36;1": "HDG", # cyan bold
    "32;1": "SUM", # green bold
    "31;1": "ERR", # red bold
    "33;1": "WRN", # yellow bold
    "30;1": "INF", # black bold
    "37"  : "INF", # white
    ""    : "OFF",
}
_statemap = {
    "CMP": "compile",
    "LNK": "link",
}
def build_msbuild(args):
    msbuild = subprocess.run(
        [os.environ["ProgramFiles(x86)"] + "\\Microsoft Visual Studio\\Installer\\vswhere.exe",
            "-latest", "-requires", "Microsoft.Component.MSBuild", "-find", "MSBuild\**\Bin\MSBuild.exe"],
        capture_output=True, text=True,
        check=True).stdout.strip()
    slnfile = ""
    for slnfile in glob.iglob(os.path.join(args.projdir, "*.sln")):
        slnfile = os.path.relpath(slnfile, args.projdir)
        break
    if args.verbose:
        subprocess.run(
            [msbuild, slnfile,
                "-v:normal",
                "-p:Configuration=" + args.config],
            cwd=args.projdir,
            check=True)
    else:
        with subprocess.Popen(
            [msbuild, slnfile,
                "-nologo",
                "-v:normal",
                "-clp:NoSummary;ShowProjectFile=false;ForceConsoleColor;ForceNoAlign",
                "-p:Configuration=" + args.config],
            cwd=args.projdir,
            text=True, encoding="utf-8", stdout=subprocess.PIPE) as pipe:
            color = "OFF"
            state = ""
            for line in pipe.stdout:
                line = line.rstrip()
                level = -1
                for span in re.split("(\x1b\\[[0-9;]*m)", line):
                    if span.startswith("\x1b"):
                        color = _colormap[span[2:-1]]
                        continue
                    if not span:
                        continue
                    if -1 == level:
                        level = int(span.startswith(" "))
                    span = span.lstrip()
                    if False:
                        # set True to debug parser
                        sys.stdout.write("%s |%s%s\n" % (color, _indent if 0 < level else "", span))
                    elif "HDG" == color:
                        state = ""
                        if span.startswith("Project ") and " is building " in span:
                            parts = span.split("\"")
                            if 5 == len(parts):
                                sys.stdout.write("%s:\n" % os.path.basename(parts[3]))
                        elif span.startswith("ClCompile:"):
                            state = "CMP"
                        elif span.startswith("Link:"):
                            state = "LNK"
                    elif "INF" == color:
                        if span.startswith("All outputs are up-to-date"):
                            state = ""
                    elif "OFF" == color and 0 < level:
                        if "CMP" == state:
                            if " " not in span:
                                sys.stdout.write("%s%s %s\n" % (_indent, _statemap[state], span))
                        elif "LNK" == state:
                            if "->" in span:
                                parts = span.split("->")
                                if 2 == len(parts):
                                    sys.stdout.write("%s%s %s\n" % (_indent, _statemap[state], os.path.basename(parts[1])))
                    elif "ERR" == color or "WRN" == color:
                        sys.stdout.write("%s\n" % span)
            exitcode = pipe.wait()
            if exitcode:
                raise subprocess.CalledProcessError(exitcode, pipe.args)

def build_make(args):
    subprocess.run(
        ["make", "--no-print-directory", "-j%s" % os.cpu_count(), "--output-sync=recurse",
            "MakeQuiet=" if args.verbose else ("MakeQuiet=@$(if $(1),echo \"%s$(1)\" && ,)" % _indent),
            "Configuration=" + args.config],
        cwd=args.projdir,
        check=True)

def build(args):
    if sys.platform.startswith("win32"):
        build_msbuild(args)
    elif sys.platform.startswith("linux"):
        build_make(args)
    else:
        raise NotImplementedError()

def guess(projdir):
    if projdir:
        return projdir
    if sys.platform.startswith("win32"):
        projdir = "VStudio"
    elif sys.platform.startswith("linux"):
        projdir = "Linux"
    return os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), "..", "build", projdir))

def main():
    p = argparse.ArgumentParser()
    p.add_argument("-v", dest="verbose", action="store_true", help="verbose")
    p.add_argument("config", help="project configuration (Debug, Release)")
    p.add_argument("projdir", nargs="?", help="project directory")
    args = p.parse_args(sys.argv[1:])
    args.projdir = guess(args.projdir)
    build(args)

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
    except subprocess.CalledProcessError as ex:
        fail(ex)
    except KeyboardInterrupt:
        fail("interrupted", 130)

if "__main__" == __name__:
    sys.dont_write_bytecode = True
    __entry()
