using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace DotnetHook
{
    public class Logger
    {
        public static bool isLogging = true;
        public static string logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "HookLog.txt");
        public static void Log(string log)
        {
            if (isLogging)
            {
                DateTime now = DateTime.Now;
                string nowStr = now.ToString("yyyy-MM-dd HH:mm:ss");
                log = String.Format("[{0}] {1}", nowStr, log);

                Console.WriteLine(log);
                using (StreamWriter w = File.AppendText(logPath))
                {
                    w.WriteLine(log);
                }
            }
        }
        public static void Log(string tag, string log)
        {
            Log(String.Format("[{0}] {1}", tag, log));
        }
    }
    public class ReflectionHelper
    {
        public static object GetValue(object obj, string fieldName, BindingFlags bindingFlags = BindingFlags.Default)
        {
            string logTag = "GetValue";
            if (bindingFlags == BindingFlags.Default)
            {
                bindingFlags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance;
            }

            Type objType = null;
            if (obj is Type) // get from class static field
            {
                objType = (Type)obj;
                obj = null;
            }
            else // get from object instance
            {
                objType = obj.GetType();
            }

            // try to find field to get
            FieldInfo field;
            field = objType.GetField(fieldName, bindingFlags);
            if (field != null)
            {
                return field.GetValue(obj);
            }

            // try to find property to get
            PropertyInfo property;
            property = objType.GetProperty(fieldName, bindingFlags);
            if (property != null)
            {
                return property.GetValue(obj);
            }
            Logger.Log(logTag, String.Format("Could not find fieldName '{0}' in object of type '{1}'", fieldName, objType.ToString()));
            return false;
        }

        public static bool SetValue(object obj, string fieldName, object value, BindingFlags bindingFlags = BindingFlags.Default)
        {
            string logTag = "SetValue";
            if (bindingFlags == BindingFlags.Default)
            {
                bindingFlags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance;
            }

            Type objType = null;
            if (obj is Type) // set to class static field
            {
                objType = (Type)obj;
                obj = null;
            }
            else // set to object instance
            {
                objType = obj.GetType();
            }

            Type valueType = value.GetType();

            // try to find field to set
            FieldInfo field;
            field = objType.GetField(fieldName, bindingFlags);
            if (field != null)
            {
                if (field.FieldType.IsAssignableFrom(valueType))
                {
                    field.SetValue(obj, value);
                    return true;
                }
                Logger.Log(logTag, String.Format("Cannot assign object of type '{0}' to '{1}'", valueType.ToString(), field.FieldType.ToString()));
                return false;
            }

            // try to find property to set
            PropertyInfo property;
            property = objType.GetProperty(fieldName, bindingFlags);
            if (property != null)
            {
                if (property.PropertyType.IsAssignableFrom(valueType))
                {
                    property.SetValue(obj, value);
                    return true;
                }
                Logger.Log(logTag, String.Format("Cannot assign object of type '{0}' to '{1}'", valueType.ToString(), property.PropertyType.ToString()));
                return false;
            }
            Logger.Log(logTag, String.Format("Could not find fieldName '{0}' in object of type '{1}'", fieldName, objType.ToString()));
            return false;
        }

        // Loops through loaded assemblies and finds the type
        public static Type GetType(string fullName)
        {
            string logTag = "GetType";
            Type t = null;
            Assembly[] assemblies = AppDomain.CurrentDomain.GetAssemblies();
            for (int i = 0; i < assemblies.Length; i++)
            {
                t = assemblies[i].GetType(fullName);
                if (t != null)
                    return t;
            }
            Logger.Log(logTag, String.Format("Could not find type '{0}' ", fullName));
            return null;
        }

        public static MethodInfo GetMethod(Type type, string methodName, BindingFlags bindingFlags = BindingFlags.Default)
        {
            string logTag = "GetMethod";
            MethodInfo method = null;
            if (bindingFlags != BindingFlags.Default)
            {
                method = type.GetMethod(methodName, bindingFlags);
            }
            else
            {
                method = type.GetMethod(methodName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance);
            }

            if (method == null)
            {
                Logger.Log(logTag, String.Format("{0} Could not find method '{0}' in object of type '{1}'", methodName, type.ToString()));
            }
            return method;
        }

        public static MethodInfo GetMethod(object obj, string methodName, BindingFlags bindingFlags = BindingFlags.Default)
        {
            if (bindingFlags == BindingFlags.Default)
                bindingFlags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;

            if (obj is Type)
                return GetMethod((Type)obj, methodName, bindingFlags);
            else
                return GetMethod(obj.GetType(), methodName, bindingFlags);
        }
    }

    internal class Natives
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        public enum PageProtection : uint
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }
    }

    public class HookHelper
    {
        private static Dictionary<MethodInfo, byte[]> hooks = new Dictionary<MethodInfo, byte[]>();

        public static void Hook(MethodInfo target, MethodInfo hook)
        {
            string logTag = "Hook";
            if (target.IsGenericMethod)
            {
                Logger.Log(logTag, String.Format("Target method '{0}' cannot be generic!", target.Name));
                return;
            }
            if (!hook.IsStatic || hook.IsGenericMethod)
            {
                Logger.Log(logTag, String.Format("Hook method '{0}' must be static and cannot be generic!", hook.Name));
                return;
            }
            if (hooks.ContainsKey(target))
            {
                Logger.Log(logTag, String.Format("Target method '{0}' is already hooked!", target.Name));
                return;
            }

            bool is64Bits = false;
            unsafe
            {
                is64Bits = sizeof(IntPtr) == 8;
            }

            // JIT compile methods
            RuntimeHelpers.PrepareMethod(target.MethodHandle);
            RuntimeHelpers.PrepareMethod(hook.MethodHandle);

            // get function pointers
            IntPtr targetAddr = target.MethodHandle.GetFunctionPointer();
            IntPtr hookAddr = hook.MethodHandle.GetFunctionPointer();

            int stubSize = (is64Bits ? 13 : 6);
            byte[] originalBytes = new byte[stubSize];

            unsafe
            {
                byte* addr = (byte*)targetAddr.ToPointer();

                // change memory protections
                uint oldProtect = VirtualProtect(targetAddr, (uint)stubSize, (uint)Natives.PageProtection.PAGE_EXECUTE_READWRITE);

                // save original instructions
                for (int i = 0; i < stubSize; i++)
                {
                    originalBytes[i] = addr[i];
                }
                hooks.Add(target, originalBytes);

                // write stub
                if (is64Bits)
                {
                    //mov r11, hookAddr
                    *addr = 0x49;
                    *(addr + 1) = 0xBB;
                    *((ulong*)(addr + 2)) = (ulong)hookAddr.ToInt64();

                    //jmp r11
                    *(addr + 10) = 0x41;
                    *(addr + 11) = 0xFF;
                    *(addr + 12) = 0xE3;
                }
                else
                {
                    //push hookAddr
                    *addr = 0x68;
                    *((uint*)(addr + 1)) = (uint)hookAddr.ToInt32();

                    //ret
                    *(addr + 5) = 0xC3;
                }

                FlushInstructionCache(targetAddr, (uint)stubSize);
                VirtualProtect(targetAddr, (uint)stubSize, oldProtect);
            }
        }

        public static void Unhook(MethodInfo target)
        {
            string logTag = "Unhook";
            if (!hooks.ContainsKey(target))
            {
                Logger.Log(logTag, String.Format("Cannot unhook method '{0}'. It was never hooked", target.Name));
                return;
            }

            byte[] originalBytes = hooks[target];
            IntPtr targetAddr = target.MethodHandle.GetFunctionPointer();

            unsafe
            {
                uint oldProtect = VirtualProtect(targetAddr, (uint)originalBytes.Length, (uint)Natives.PageProtection.PAGE_EXECUTE_READWRITE);

                byte* addr = (byte*)targetAddr.ToPointer();
                for (int i = 0; i < originalBytes.Length; i++)
                {
                    *(addr + i) = originalBytes[i];
                }

                FlushInstructionCache(targetAddr, (uint)originalBytes.Length);
                VirtualProtect(targetAddr, (uint)originalBytes.Length, oldProtect);
            }
            hooks.Remove(target);
        }

        private static uint VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect)
        {
            uint oldProtect;

            if (!Natives.VirtualProtect(lpAddress, (UIntPtr)dwSize, flNewProtect, out oldProtect))
            {
                throw new Win32Exception();
            }
            return oldProtect;
        }
        private static void FlushInstructionCache(IntPtr address, uint size)
        {
            if (!Natives.FlushInstructionCache(Natives.GetCurrentProcess(), address, (UIntPtr)size))
            {
                throw new Win32Exception();
            }
        }
    }
}