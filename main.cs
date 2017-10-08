/*
AntiDebugger in c# by d3z3n0v3
data 10/09/17 -
memories: 0x00010002 - 0x80010001
buffer vulnerability
*/

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;


namespace debugging
{
    internal class ProgramBase : Program { public static void Main(string[] args) => Start(new List<string>(new string[] { "dnSpy", "dnSpy-x86", "MegaDumper" }), args); }

    class Program
    {
        public static void Start(List<string> processes, string[] args) { Console.Title = "AntiDebugger 1.0.0"; Console.WriteLine("AntiDebugger by d3z3n0v3."); AntiDebugger.Start(args); OnDebugging(processes, args); }
        public static void OnDebugging(List<string> processes, string[] args) { foreach (string process in processes) if (IsOpened(process)) KillProcess(process); Loop(args); }
        public static bool IsOpened(string process) { Process[] proc = Process.GetProcessesByName(process); if (proc.Length > 0) return true; else return false; }
        public static void KillProcess(string process) { Process[] proc = Process.GetProcessesByName(process); foreach (Process p in proc) Environment.Exit(1); }
        public static void Loop(string[] args) { OnDebugging(new List<string>(new string[] { "dnSpy", "dnSpy-x86", "MegaDumper" }), args); }
    }

    class AntiDebugger
    {
        const int DBG_CONTINUE = 0x00010002;
        const int DBG_EXCEPTION_NOT_HANDLED = unchecked((int)0x80010001);

        enum DebugEventType : int
        {
            CREATE_PROCESS_DEBUG_EVENT = 3,
            CREATE_THREAD_DEBUG_EVENT = 2,
            EXCEPTION_DEBUG_EVENT = 1,
            EXIT_PROCESS_DEBUG_EVENT = 5,
            EXIT_THREAD_DEBUG_EVENT = 4,
            LOAD_DLL_DEBUG_EVENT = 6,
            OUTPUT_DEBUG_STRING_EVENT = 8,
            RIP_EVENT = 9,
            UNLOAD_DLL_DEBUG_EVENT = 7,
        }

        [StructLayout(LayoutKind.Sequential)]
        struct DEBUG_EVENT
        {
            [MarshalAs(UnmanagedType.I4)]
            public DebugEventType dwDebugEventCode;
            public int dwProcessId;
            public int dwThreadId;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
            public byte[] bytes;
        }

        [DllImport("Kernel32.dll", SetLastError = true)]
        static extern bool DebugActiveProcess(int dwProcessId);
        [DllImport("Kernel32.dll", SetLastError = true)]
        static extern bool WaitForDebugEvent([Out] out DEBUG_EVENT lpDebugEvent, int dwMilliseconds);
        [DllImport("Kernel32.dll", SetLastError = true)]
        static extern bool ContinueDebugEvent(int dwProcessId, int dwThreadId, int dwContinueStatus);
        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern bool IsDebuggerPresent();

        public static void Start(string[] args)
        {
            DebugSelf(args);
        }

        static void DebuggerThread(object arg)
        {
            DEBUG_EVENT evt = new DEBUG_EVENT();
            evt.bytes = new byte[1024];

            if (!DebugActiveProcess((int)arg))
                throw new Win32Exception();

            while (true)
            {
                if (!WaitForDebugEvent(out evt, -1))
                    throw new Win32Exception();
                int continueFlag = DBG_CONTINUE;
                if (evt.dwDebugEventCode == DebugEventType.EXCEPTION_DEBUG_EVENT)
                    continueFlag = DBG_EXCEPTION_NOT_HANDLED;
                ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, continueFlag);
            }
        }

        public static void DebugSelf(string[] args)
        {
            Process self = Process.GetCurrentProcess();

            if (args.Length == 2 && args[0] == "--debug-attach")
            {
                int owner = int.Parse(args[1]);
                Process pdbg = Process.GetProcessById(owner);
                new Thread(KillOnExit) { IsBackground = true, Name = "KillOnExit" }.Start(pdbg);
                WaitForDebugger();
                DebuggerThread(owner);
                Environment.Exit(1);
            }
            else
            {
                ProcessStartInfo psi =
                new ProcessStartInfo(Environment.GetCommandLineArgs()[0], "--debug-attach " + self.Id)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    ErrorDialog = false,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                Process pdbg = Process.Start(psi);
                if (pdbg == null)
                    throw new ApplicationException("Unable to debug");
                new Thread(KillOnExit) { IsBackground = true, Name = "KillOnExit" }.Start(pdbg);
                new Thread(DebuggerThread) { IsBackground = true, Name = "DebuggerThread" }.Start(pdbg.Id);
                WaitForDebugger();
            }
        }

        static void WaitForDebugger()
        {
            DateTime start = DateTime.Now;
            while (!IsDebuggerPresent())
            {
                if ((DateTime.Now - start).TotalMinutes > 1)
                    throw new TimeoutException("Debug operation timeout.");
                Thread.Sleep(1);
            }
        }
        static void KillOnExit(object process)
        {
            string p = ((Process)process).ProcessName;
            ((Process)process).WaitForExit();
            System.Windows.Forms.MessageBox.Show($"[Process: {p}]\nDebbuger detected! Exiting...", "AntiDebugger #d3z3n0v3", System.Windows.Forms.MessageBoxButtons.OK, System.Windows.Forms.MessageBoxIcon.Information);
            Environment.Exit(1);
        }
    }
}
