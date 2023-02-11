#!/usr/bin/python

import argparse, glob, os, re, subprocess, sys, tempfile

_indent = "  "

def iterloglines(proc, pattern):
    logs = []
    indx = 0
    file = None
    done = False
    try:
        while not done:
            try:
                proc.wait(0.5)
                done = True
            except subprocess.TimeoutExpired:
                pass
            newlogs = set(glob.iglob(pattern)).difference(logs)
            logs.extend(sorted(newlogs))
            loop = True
            while loop and len(logs) > indx:
                if "build.log" == os.path.basename(logs[indx]):
                    indx += 1
                    continue
                if not file:
                    file = open(logs[indx], "rt", encoding="utf-8")
                    prev = ""
                loop = done
                for line in file:
                    if done or line.endswith("\n"):
                        yield prev + line
                        prev = ""
                        if "Done Building Project" in line:
                            loop = True
                            break
                    else:
                        prev += line
                        break
                if loop:
                    file.close()
                    file = None
                    indx += 1
    finally:
        if file:
            file.close()

_line_re = re.compile(r"^([ \t]*)(?:\d+>)?(.*?)(?: *[(][^:]+:\d+[)])?$")
_fail_re = re.compile(r"^(?:[A-Za-z]:)?[^:]+: *(?:error|warning)")
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
    with tempfile.TemporaryDirectory() as tempdir:
        with subprocess.Popen(
            [msbuild, slnfile,
                "-m:%s" % os.cpu_count(),
                "-nologo",
                "-noconlog",
                "-v:normal",
                "-dfl",
                "-flp:LogFile=%s;Encoding=UTF-8;Verbosity=normal;NoSummary" % os.path.join(tempdir, "build.log"),
                "-p:Configuration=" + args.config],
            cwd=args.projdir) as proc:
            state, level = "", 0
            for line in iterloglines(proc, os.path.join(tempdir, "build*.log")):
                line = line.rstrip()
                if line.startswith("Logging verbosity "):
                    i = line.find("1>Project")
                    if 0 <= i:
                        line = "     " + line[i:]
                if args.verbose:
                    print(line)
                    continue
                m = _line_re.search(line)
                line_level = 0
                if m:
                    line_level = len(m.group(1))
                    line = m.group(2)
                if line.startswith("Project "):
                    parts = line.split("\"")
                    if 5 == len(parts):
                        print("%s:" % os.path.basename(parts[3]))
                    elif 3 == len(parts) and not parts[1].endswith(".sln"):
                        print("%s:" % os.path.basename(parts[1]))
                elif line.startswith("ClCompile:"):
                    state, level = "compile", line_level
                elif line.startswith("Link:"):
                    state, level = "link", line_level
                elif _fail_re.search(line):
                    print(line)
                elif line_level <= level or line.startswith("All outputs are up-to-date"):
                    state, level = "", 0
                elif "compile" == state:
                    if " " not in line:
                        print("%s%s %s" % (_indent, state, line))
                elif "link" == state:
                    if "->" in line:
                        parts = line.split("->")
                        if 2 == len(parts):
                            print("%s%s %s" % (_indent, state, os.path.basename(parts[1])))
            exitcode = proc.wait()
            if exitcode:
                raise subprocess.CalledProcessError(exitcode, proc.args)

def build_make(args):
    subprocess.run(
        ["make",
            "-j%s" % os.cpu_count(),
            "--no-print-directory",
            "--output-sync=recurse",
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
