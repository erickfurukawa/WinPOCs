using System;
using System.Net.Sockets;
using System.Net;
using System.Text;
using Microsoft.CSharp;
using System.CodeDom.Compiler;
using System.IO;
using System.Reflection;
using System.Linq;

namespace CSCodeInjection
{
    public class Server
    {
        static int bufferSize = 256 * 1024;
        static void Main(string[] args)
        {
            StartServer("7777:secret");
        }

        static int StartServer(string args)
        {
            string[] argsList = args.Split(':');
            int port = Int32.Parse(argsList[0]);
            string secret = argsList[1];
            Console.WriteLine("Injection server --------------------------------------------------------------");

            TcpListener listener = null;
            try
            {
                // Create a TCP listener
                listener = new TcpListener(IPAddress.Loopback, port);
                listener.Start();

                Console.WriteLine("Listening on port {0}...", port);
                while (true)
                {
                    // Accept incoming client connections
                    TcpClient client = listener.AcceptTcpClient();
                    Console.WriteLine("Client connected: {0}", client.Client.RemoteEndPoint);

                    // Handle client request in a separate thread
                    System.Threading.ThreadPool.QueueUserWorkItem(state => HandleClient(client, secret));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: {0}", ex.Message);
            }
            finally
            {
                // Stop listening and clean up
                listener?.Stop();
            }

            return 0;
        }
        static void HandleClient(TcpClient client, string secret)
        {
            NetworkStream stream = client.GetStream();
            string code;
            string methodName;
            string receivedSecret;

            if (ReadMessage(stream, out receivedSecret))
            {
                Console.WriteLine("Received secret: {0}", receivedSecret);
                if (receivedSecret == secret)
                {
                    SendMessage(stream, "Correct secret.");
                    while (ReadMessage(stream, out methodName) && ReadMessage(stream, out code))
                    {
                        Console.WriteLine("Received: {0}", code);
                        Console.WriteLine("Calling: {0}", methodName);
                        SendMessage(stream, RunString(code, methodName));
                    }
                }
                else
                {
                    SendMessage(stream, "Incorrect secret.");
                }
            }
            Console.WriteLine("Client disconnected: {0}", client.Client.RemoteEndPoint);
            client.Close();
        }
        static bool ReadMessage(NetworkStream stream, out string message)
        {
            byte[] buffer = new byte[bufferSize];
            try
            {
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                // Convert received bytes to string
                message = Encoding.ASCII.GetString(buffer, 0, bytesRead);
            }
            catch (IOException)
            {
                // Client disconnected
                message = "";
                return false;
            }
            return true;
        }
        static bool SendMessage(NetworkStream stream, string message)
        {
            try
            {
                byte[] dataToSend = Encoding.ASCII.GetBytes(message);
                stream.Write(dataToSend, 0, dataToSend.Length);
            }
            catch (IOException)
            {
                // Client disconnected
                return false;
            }
            return true;
        }

        static string RunString(string code, string methodFullName)
        {
            int index = methodFullName.LastIndexOf(".");
            string typeName = methodFullName.Substring(0, index);
            string methodName = methodFullName.Substring(index + 1, methodFullName.Length - index - 1);
            string returnData = "";
            try
            {
                // Set up the compiler parameters
                var compilerParams = new CompilerParameters();
                var assemblies = AppDomain.CurrentDomain
                            .GetAssemblies()
                            .Where(a => !a.IsDynamic)
                            .Select(a => a.Location);
                compilerParams.ReferencedAssemblies.AddRange(assemblies.ToArray());
                compilerParams.CompilerOptions = "/unsafe";
                compilerParams.GenerateInMemory = true;

                // Create a new CSharpCodeProvider instance
                var codeProvider = new CSharpCodeProvider();

                // Compile the code
                CompilerResults results = codeProvider.CompileAssemblyFromSource(compilerParams, code);

                if (results.Errors.HasErrors)
                {
                    Console.WriteLine("Compilation error:");
                    foreach (CompilerError error in results.Errors)
                    {
                        Console.WriteLine(error.ErrorText);
                        returnData = error.ErrorText;
                    }
                }
                else
                {
                    // Get the compiled assembly and invoke method
                    Assembly assembly = results.CompiledAssembly;
                    object instance = assembly.CreateInstance(typeName);
                    MethodInfo method = assembly.GetType(typeName)?.GetMethod(methodName);

                    if (method != null)
                    {
                        returnData = method.Invoke(instance, null)?.ToString();
                    }
                    else
                    {
                        Console.WriteLine("Could not find method " + methodFullName);
                        returnData = "Could not find method " + methodFullName;
                    }
                }
            }
            catch (Exception e) 
            {
                Console.WriteLine(e.Message);
                returnData = e.Message;
            }

            if (returnData != null)
                return returnData;
            return "(null)";
        }
    }
}