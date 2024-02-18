using System.Net;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using System.Text;
using System.Text.Json.Serialization;

namespace PcapParser.Net;

public class PcapAnalyzer
{
    public string InputFile { get; init; }
    public string[] Filter { get; set; }
    public string Exclude { get; set; }
    private const string _orFilter = "or";
    private const string _andFilter = "and";
    private const string _whitespace = " ";

    private string CreateFilterText()
    {
        StringBuilder Builder = new StringBuilder();
        Builder.Append("(");
        foreach (string expression in Filter)
        {
            Builder.Append(expression).Append(_whitespace).Append(_orFilter).Append(_whitespace);
        }
        Builder.Remove(Builder.Length - 4, 4).Append(")");

        if (Exclude is not null)
        {
            Builder.Append(_andFilter).Append("(").Append(Exclude).Append(")");
        }


        return Builder.ToString();
    }

    public void PrintFlow(List<NetFlow> Flow)
    {
        foreach (NetFlow SingleFlow in Flow)
        {
            Console.WriteLine($"{SingleFlow.Type}:{SingleFlow.Source} --> {SingleFlow.Destination}:{SingleFlow.DestinationPort}");
        }
    }

    public List<NetFlow> ParsePcap()
    {
        using (CaptureFileReaderDevice Reader = new CaptureFileReaderDevice(InputFile))
        {
            List<NetFlow> AllFlows = new List<NetFlow>();

            PacketCapture Cap;
            Reader.Open(DeviceModes.None);
            Reader.Filter = CreateFilterText();
            while (true)
            {
                Reader.GetNextPacket(out Cap);
                RawCapture Raw;
                try
                {
                    Raw = Cap.GetPacket();
                }
                catch (NullReferenceException ex)
                {
                    break;
                }

                Packet LinkLayer = Packet.ParsePacket(Raw.LinkLayerType, Raw.Data);
                if (LinkLayer.PayloadPacket is IPv4Packet)
                {
                    IPv4Packet Packet = (IPv4Packet)LinkLayer.PayloadPacket;
                    if (Packet.PayloadPacket is TcpPacket)
                    {
                        TcpPacket TcpPacket = (TcpPacket)Packet.PayloadPacket;
                        bool NotExists = AllFlows.Where(flow => flow.Source.Equals(Packet.SourceAddress) && flow.Destination.Equals(Packet.DestinationAddress) && flow.DestinationPort == TcpPacket.DestinationPort).Count() == 0;

                        if (NotExists == true)
                        {
                            AllFlows.Add(new NetFlow()
                            {
                                Source = Packet.SourceAddress,
                                Destination = Packet.DestinationAddress,
                                DestinationPort = TcpPacket.DestinationPort,
                                Type = NetFlowType.TCP
                            });
                        }
                    }
                    else if (Packet.PayloadPacket is UdpPacket)
                    {
                        UdpPacket UdpPacket = (UdpPacket)Packet.PayloadPacket;
                        bool NotExists = AllFlows.Where(flow => flow.Source.Equals(Packet.SourceAddress) && flow.Destination.Equals(Packet.DestinationAddress) && flow.DestinationPort == UdpPacket.DestinationPort).Count() == 0;

                        if (NotExists == true)
                        {
                            AllFlows.Add(new NetFlow()
                            {
                                Source = Packet.SourceAddress,
                                Destination = Packet.DestinationAddress,
                                DestinationPort = UdpPacket.DestinationPort,
                                Type = NetFlowType.UDP
                            });
                        }
                    }
                    else if (Packet.PayloadPacket is IcmpV4Packet)
                    {
                        IcmpV4Packet IcmpPacket = (IcmpV4Packet)Packet.PayloadPacket;
                        bool NotExists = AllFlows.Where(flow => flow.Source.Equals(Packet.SourceAddress) && flow.Destination.Equals(Packet.DestinationAddress) && flow.Type == NetFlowType.ICMP).Count() == 0;

                        if (NotExists == true)
                        {
                            AllFlows.Add(new NetFlow()
                            {
                                Source = Packet.SourceAddress,
                                Destination = Packet.DestinationAddress,
                                DestinationPort = 0,
                                Type = NetFlowType.ICMP
                            });
                        }
                    }
                }
            }

            return AllFlows;
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
