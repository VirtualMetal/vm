#!/usr/bin/python

# @file tools/build.py
#
# @copyright 2022 Bill Zissimopoulos
#
# This file is part of VirtualMetal.
#
# You can redistribute it and/or modify it under the terms of the GNU
# Affero General Public License version 3 as published by the Free
# Software Foundation.

import argparse, glob, hashlib, os, subprocess, sys, tempfile

_indent = "  "

def build_msbuild(args):
    msbuild = subprocess.run(
        [os.environ["ProgramFiles(x86)"] + "\\Microsoft Visual Studio\\Installer\\vswhere.exe",
            "-latest", "-requires", "Microsoft.Component.MSBuild", "-find", "MSBuild\**\Bin\MSBuild.exe"],
        capture_output=True, text=True,
        check=True).stdout.strip()
    arg0hash = hashlib.sha256(os.path.abspath(sys.argv[0]).encode("utf-8")).hexdigest()[:16]
    cachedir = os.path.join(tempfile.gettempdir(), arg0hash)
    os.makedirs(cachedir, exist_ok=True)
    logdll = os.path.join(cachedir, "build.MsbuildLogger.dll")
    logsrc = os.path.join(os.path.dirname(sys.argv[0]), "build.MsbuildLogger.cs")
    if not os.path.exists(logdll) or os.path.getmtime(logdll) < os.path.getmtime(logsrc):
        print("compiling: " + logsrc + " -> " + logdll)
        subprocess.run(
            [os.environ["SystemRoot"] + "\\Microsoft.NET\\Framework\\v3.5\\csc.exe",
                "-nologo",
                "-t:library",
                "-r:" + os.path.join(os.path.dirname(msbuild), "Microsoft.Build.Framework.dll"),
                "-r:" + os.path.join(os.path.dirname(msbuild), "Microsoft.Build.Utilities.Core.dll"),
                "-out:" + logdll,
                logsrc],
            check=True)
    slnfile = ""
    for slnfile in glob.iglob(os.path.join(args.projdir, "*.sln")):
        slnfile = os.path.relpath(slnfile, args.projdir)
        break
    with subprocess.Popen(
        [msbuild, slnfile,
            "-m:%s" % os.cpu_count(),
            "-nologo",
            "-noconlog",
            "-verbosity:quiet",
            "-logger:VirtualMetal.Build.MsbuildLogger,%s;%s" % (
                logdll,
                "verbose" if args.verbose else "normal"),
            "-p:Configuration=" + args.config],
        cwd=args.projdir,
        text=True, encoding="utf-8", stdout=subprocess.PIPE) as pipe:
        projmap = {}
        projlst = []
        projind = 0
        done = False
        while not done:
            line = pipe.stdout.readline()
            done = "" == line
            line = line.rstrip()
            part = line.split(":", maxsplit=1)
            if part[0]:
                id = int(part[0])
                if id not in projmap:
                    projmap[id] = []
                    projlst.append(id)
                projmap[id].append(part[1])
            while projind < len(projlst):
                id = projlst[projind]
                for l in projmap[id]:
                    if "" == l or (not l.startswith(" ") and l.endswith(".sln:")):
                        projind += 1
                        break
                    print(l)
                projmap[id] = []
                if not done:
                    break
        exitcode = pipe.wait()
        if exitcode:
            raise subprocess.CalledProcessError(exitcode, pipe.args)

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
