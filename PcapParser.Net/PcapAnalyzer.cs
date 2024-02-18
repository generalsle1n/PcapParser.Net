using System.Net;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using System.Text;

namespace PcapParser.Net;

public class PcapAnalyzer
{
    public string InputFile { get; init; }
    public string[] Filter { get; set; }
    private const string _orFilter = "or";
    private const string _whitespace = " ";

    private string CreateFilterText()
    {
        StringBuilder Builder = new StringBuilder();

        foreach (string expression in Filter)
        {
            Builder.Append(expression).Append(_whitespace).Append(_orFilter).Append(_whitespace);
        }
        Builder.Remove(Builder.Length - 4, 4);

        return Builder.ToString();
    }

    public void ParsePcap()
    {
        using (CaptureFileReaderDevice Reader = new CaptureFileReaderDevice(InputFile))
        {
            PacketCapture Cap;
            Reader.Open(DeviceModes.None);
            Reader.Filter = CreateFilterText();
            while (true)
            {
                Reader.GetNextPacket(out Cap);
                RawCapture Raw = Cap.GetPacket();
                Packet LinkLayer = Packet.ParsePacket(Raw.LinkLayerType, Raw.Data);
                if (LinkLayer.PayloadPacket is IPv4Packet)
                {
                    IPv4Packet Packet = (IPv4Packet)LinkLayer.PayloadPacket;
                    if (Packet.PayloadPacket is TcpPacket)
                    {
                        TcpPacket TcpPacket = (TcpPacket)Packet.PayloadPacket;
                        Console.WriteLine($"{Packet.SourceAddress} --> {Packet.DestinationAddress}:{TcpPacket.DestinationPort}");
                    }
                    else if (Packet.PayloadPacket is UdpPacket)
                    {
                        UdpPacket UdpPacket = (UdpPacket)Packet.PayloadPacket;
                        Console.WriteLine($"{Packet.SourceAddress} --> {Packet.DestinationAddress}:{UdpPacket.DestinationPort}");
                    }
                }
            }
        }
    }
}

public class NetFlow
{
    public IPAddress Source { get; set; }
    public IPAddress Destination { get; set; }
    public int DestinationPort { get; set; }
    public NetFlowType Type { get; set; }
}

public enum NetFlowType
{
    TCP,
    UDP
}
