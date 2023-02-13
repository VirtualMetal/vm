/**
 * @file tools/build.MsbuildLogger.cs
 *
 * @copyright 2022 Bill Zissimopoulos
 */
/*
 * This file is part of VirtualMetal.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * Affero General Public License version 3 as published by the Free
 * Software Foundation.
 */

using System;
using System.IO;
using System.Security;
using System.Collections.Generic;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

namespace VirtualMetal.Build
{
    public class MsbuildLogger : Logger
    {
        public override void Initialize(IEventSource EventSource)
        {
            switch (Parameters)
            {
            default:
                Style = OutputStyle.Normal;
                break;
            case "verbose":
                Style = OutputStyle.Verbose;
                break;
            case "xml":
                Style = OutputStyle.Xml;
                break;
            }
            EventSource.ProjectStarted += (Sender, Args) => EventStarted(Sender, Args, true);
            EventSource.ProjectFinished += (Sender, Args) => EventFinished(Sender, Args);
            EventSource.TargetStarted += (Sender, Args) => EventStarted(Sender, Args, false);
            EventSource.TargetFinished += (Sender, Args) => EventFinished(Sender, Args);
            EventSource.ErrorRaised += (Sender, Args) => EventRaised(Sender, Args);
            EventSource.WarningRaised += (Sender, Args) => EventRaised(Sender, Args);
            EventSource.MessageRaised += (Sender, Args) => EventRaised(Sender, Args);
        }
        private void EventStarted(object Sender, BuildEventArgs Args, bool Immediate)
        {
            var Stack = GetStackForArgs(Args);
            if (Immediate)
                ImmediateLogEvent(Stack.Count, Args);
            Stack.Push(new WrappedArgs(Args, Immediate));
        }
        private void EventFinished(object Sender, BuildEventArgs Args)
        {
            var Stack = GetStackForArgs(Args);
            var Wrapped = Stack.Pop();
            if (Wrapped.Logged)
                ImmediateLogEvent(Stack.Count, Args);
        }
        private void EventRaised(object Sender, BuildEventArgs Args)
        {
            var Bmea = Args as BuildMessageEventArgs;
            if (null == Bmea ||
                Bmea.Importance == MessageImportance.High ||
                (Bmea.Importance == MessageImportance.Normal &&
                    (Style != OutputStyle.Normal || Args.Message.StartsWith(AllOutputsAreUpToDate))))
                LogEvent(Args);
        }
        private void LogEvent(BuildEventArgs Args)
        {
            var Stack = GetStackForArgs(Args);
            if (0 < Stack.Count)
            {
                var Wrapped = Stack.Peek();
                if (!Wrapped.Logged)
                {
                    Wrapped.Logged = true;
                    ImmediateLogEvent(Stack.Count - 1, Wrapped.Args);
                }
            }
            ImmediateLogEvent(Stack.Count, Args);
        }
        private void ImmediateLogEvent(int Level, BuildEventArgs Args)
        {
            string Line;
            switch (Style)
            {
            default:
                Line = NormalLogLine(Args);
                break;
            case OutputStyle.Verbose:
                Line = VerboseLogLine(Args);
                break;
            case OutputStyle.Xml:
                Line = XmlLogLine(Args);
                break;
            }
            if (null == Line)
                return;
            int Id = null != Args.BuildEventContext && 0 <= Args.BuildEventContext.ProjectInstanceId ?
                Args.BuildEventContext.ProjectInstanceId : -1;
            Out.WriteLine("{0}:{1}",
                0 <= Id ? Id.ToString() : "",
                Line);
        }
        private string NormalLogLine(BuildEventArgs Args)
        {
            if (Args is ProjectStartedEventArgs)
            {
                var Psea = (ProjectStartedEventArgs)Args;
                return String.Format("{0}:", Path.GetFileName(Psea.ProjectFile));
            }
            else if (Args is ProjectFinishedEventArgs)
                return "";
            else if (Args is BuildErrorEventArgs)
            {
                var Beea = (BuildErrorEventArgs)Args;
                var Code = String.Format("error {0}", Beea.Code).Trim();
                return
                    String.Format("  {0}:{1}:{2}: {3}: ", Beea.File, Beea.LineNumber, Beea.ColumnNumber, Code) +
                    FlattenMessage(Args.Message);
            }
            else if (Args is BuildWarningEventArgs)
            {
                var Bwea = (BuildWarningEventArgs)Args;
                var Code = String.Format("warning {0}", Bwea.Code).Trim();
                return
                    String.Format("  {0}:{1}:{2}: {3}: ", Bwea.File, Bwea.LineNumber, Bwea.ColumnNumber, Code) +
                    FlattenMessage(Args.Message);
            }
            else if (Args is BuildMessageEventArgs)
            {
                var Bmea = (BuildMessageEventArgs)Args;
                var Stack = GetStackForArgs(Args);
                if (0 == Stack.Count)
                    return null;
                var Wrapped = Stack.Peek();
                if (!(Wrapped.Args is TargetStartedEventArgs))
                    return null;
                if (Wrapped.Suppress)
                    return null;
                var Message = FlattenMessage(Args.Message);
                if (Message.StartsWith(AllOutputsAreUpToDate))
                {
                    Wrapped.Suppress = true;
                    return null;
                }
                switch (((TargetStartedEventArgs)Wrapped.Args).TargetName)
                {
                case "ClCompile":
                    if (Message.Contains(" "))
                        return null;
                    return String.Format("  compile {0}", Message);
                case "Link":
                    var Parts = Message.Split(Arrow, StringSplitOptions.None);
                    if (2 != Parts.Length)
                        return null;
                    return String.Format("  link {0}", Path.GetFileName(Parts[1].Trim()));
                }
                return null;
            }
            else
                return null;
        }
        private string VerboseLogLine(BuildEventArgs Args)
        {
            if (Args is ProjectStartedEventArgs)
            {
                var Psea = (ProjectStartedEventArgs)Args;
                return String.Format("{0}:", Psea.ProjectFile);
            }
            else if (Args is ProjectFinishedEventArgs)
                return "";
            else if (Args is TargetStartedEventArgs)
            {
                var Tsea = (TargetStartedEventArgs)Args;
                return String.Format("  {0}:", Tsea.TargetName);
            }
            else if (Args is BuildErrorEventArgs)
            {
                var Beea = (BuildErrorEventArgs)Args;
                var Code = String.Format("error {0}", Beea.Code).Trim();
                return
                    String.Format("    {0}:{1}:{2}: {3}: ", Beea.File, Beea.LineNumber, Beea.ColumnNumber, Code) +
                    FlattenMessage(Args.Message);
            }
            else if (Args is BuildWarningEventArgs)
            {
                var Bwea = (BuildWarningEventArgs)Args;
                var Code = String.Format("warning {0}", Bwea.Code).Trim();
                return
                    String.Format("    {0}:{1}:{2}: {3}: ", Bwea.File, Bwea.LineNumber, Bwea.ColumnNumber, Code) +
                    FlattenMessage(Args.Message);
            }
            else if (Args is BuildMessageEventArgs)
            {
                var Bmea = (BuildMessageEventArgs)Args;
                return
                    "    " +
                    FlattenMessage(Args.Message);
            }
            else
                return null;
        }
        private string XmlLogLine(BuildEventArgs Args)
        {
            if (Args is ProjectStartedEventArgs)
            {
                var Psea = (ProjectStartedEventArgs)Args;
                return String.Format("<Project File='{0}'>", Psea.ProjectFile);
            }
            else if (Args is ProjectFinishedEventArgs)
            {
                var Pfea = (ProjectFinishedEventArgs)Args;
                return String.Format("<BuildStatus Success='{0}'></Project>", Pfea.Succeeded);
            }
            else if (Args is TargetStartedEventArgs)
            {
                var Tsea = (TargetStartedEventArgs)Args;
                return String.Format("<Target Name='{0}'>", Tsea.TargetName);
            }
            else if (Args is TargetFinishedEventArgs)
                return "</Target>";
            else if (Args is BuildErrorEventArgs)
            {
                var Beea = (BuildErrorEventArgs)Args;
                return
                    String.Format("<Error File='{0}' Line='{1}' Column='{2}'>", Beea.File, Beea.LineNumber, Beea.ColumnNumber) +
                    FlattenMessage(SecurityElement.Escape(Args.Message)) + "</Error>";
            }
            else if (Args is BuildWarningEventArgs)
            {
                var Bwea = (BuildWarningEventArgs)Args;
                return
                    String.Format("<Warning File='{0}' Line='{1}' Column='{2}'>", Bwea.File, Bwea.LineNumber, Bwea.ColumnNumber) +
                    FlattenMessage(SecurityElement.Escape(Args.Message)) + "</Warning>";
            }
            else if (Args is BuildMessageEventArgs)
            {
                var Bmea = (BuildMessageEventArgs)Args;
                var Type = Bmea.GetType().Name.Replace("EventArgs", "");
                return
                    String.Format("<Message Type='{0}' Importance='{1}'>", Type, Bmea.Importance) +
                    FlattenMessage(SecurityElement.Escape(Args.Message)) + "</Message>";
            }
            else
                return "<UNKNOWN />";
        }
        private string FlattenMessage(string Message)
        {
            return Message.Replace("\r", "").Replace("\n", "&#10;");
        }
        private Stack<WrappedArgs> GetStackForArgs(BuildEventArgs Args)
        {
            Stack<WrappedArgs> Stack;
            int Id = null != Args.BuildEventContext && 0 <= Args.BuildEventContext.ProjectInstanceId ?
                Args.BuildEventContext.ProjectInstanceId : -1;
            if (!stacks.TryGetValue(Id, out Stack))
            {
                Stack = new Stack<WrappedArgs>();
                stacks.Add(Id, Stack);
            }
            return Stack;
        }
        private class WrappedArgs
        {
            public WrappedArgs(BuildEventArgs Args, bool Logged)
            {
                this.Args = Args;
                this.Logged = Logged;
            }
            public BuildEventArgs Args;
            public bool Logged;
            public bool Suppress;
        }
        enum OutputStyle
        {
            Normal,
            Verbose,
            Xml,
        };
        private OutputStyle Style;
        private TextWriter Out = Console.Out;
        private Dictionary<int, Stack<WrappedArgs>> stacks =
            new Dictionary<int, Stack<WrappedArgs>>();
        private static string[] Arrow = new String[]{ "->" };
        private static string AllOutputsAreUpToDate = "All outputs are up-to-date";
    }
}
