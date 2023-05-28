using System;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace CSCodeInjection
{
    internal class Client
    {
        static void Main(string[] args)
        {
            string serverAddress = "127.0.0.1";
            int port = Int32.Parse(args[0]);
            string secret = args[1];
            string codePath = args[2];
            string serverResponse;

            try
            {
                TcpClient client = new TcpClient(serverAddress, port);
                Console.WriteLine("Connected to server {0}:{1}", serverAddress, port);
                NetworkStream stream = client.GetStream();

                Console.WriteLine("Sending secret...");
                SendMessage(stream, secret);
                ReadMessage(stream, out serverResponse);
                Console.WriteLine("Message from server: {0}", serverResponse);

                Console.WriteLine("Sending code...");
                string code = File.ReadAllText(codePath);
                SendMessage(stream, code);
                ReadMessage(stream, out serverResponse);
                Console.WriteLine("Message from server: {0}", serverResponse);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: {0}", ex.Message);
            }
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
                return false;
            }
            return true;
        }
    }
}