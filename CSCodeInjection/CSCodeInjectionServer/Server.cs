using System;
using System.Net.Sockets;
using System.Net;
using System.Text;
using Microsoft.CSharp;
using System.CodeDom.Compiler;
using System.IO;
using System.Reflection;

namespace CSCodeInjection
{
    public class Server
    {
        static void Main(string[] args)
        {
            StartServer("7777:secret");
        }

        //public static void StartServer(int port, string secret)
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
            string message;
            string receivedSecret;

            if (ReadMessage(stream, out receivedSecret))
            {
                Console.WriteLine("Received secret: {0}", receivedSecret);
                if (receivedSecret == secret)
                {
                    SendMessage(stream, "Correct secret.");
                    while (ReadMessage(stream, out message))
                    {
                        Console.WriteLine("Received: {0}", message);
                        SendMessage(stream, RunString(message));
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
            byte[] buffer = new byte[4 * 1024];
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

        static string RunString(string code)
        {
            string returnData = "(return value)";
            try
            {
                // Set up the compiler parameters
                var compilerParams = new CompilerParameters();
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
                    // Get the compiled assembly
                    Assembly assembly = results.CompiledAssembly;

                    // Create an instance of the class
                    object instance = assembly.CreateInstance("InjectionClass");

                    // Invoke the method dynamically
                    MethodInfo method = instance.GetType().GetMethod("Main");
                    method.Invoke(instance, null);
                }
            }
            catch (Exception) { }

            return returnData;
        }
    }
}