#pragma warning disable 1591

using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Frends.Community.SecurityThreatDiagnostics
{
    /// <summary>
    /// This class is responsible for transmitting the validation parameters from the runtime configuration into process of security diagnostics.
    /// </summary>
    public class Validation
    {
        /// <summary>
        /// The payload or the attribute value to be validated.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")] 
        [DefaultValue("{{#trigger.data.body.}}")]
        public string Payload { get; set; }
    }
    
    /// <summary>
    /// This class is responsible for transmitting the validation attributes from the runtime configuration into process of security diagnostics.
    /// </summary>
    public class ValidationAttributes
    {
        /// <summary>
        /// The payload or the attribute value to be validated.
        /// </summary>
        [DefaultValue("{{#trigger.data.body.}}")]
        public OptionalAttribute[] optionalAttributes { get; set; }
        //public Dictionary<string, bool> Attribute { get; set; }
        public class OptionalAttribute
        {
            public string Attribute { get; set; }
            public bool Enabled{ get; set; }
        }
        
    }
    
    /// <summary>
    /// Challenge against allowed IP addresses
    /// </summary>
    public class AllowedIPAddresses
    {
        /// <summary>
        /// Current HTTP url where the message is coming from
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")] 
        [DefaultValue("Current HTTP url")]
        public string Host { get; set; }

        /// <summary>
        /// Whitelisted IP addresses to be bypassed by the process engine's validation
        /// </summary>
        [DefaultValue("\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}")]
        public string[] WhiteListedIpAddress { get; set; }

        /// <summary>
        /// Blacklisted IP addresses and ranges which will be blocked by the process execution engine 
        /// </summary>
        [DefaultValue("\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}")]
        public string[] BlackListedIpAddresses { get; set; }
    }

    /// <summary>
    /// Challenge against allowed HTTP headers
    /// </summary>
    [DefaultValue("{{#trigger.data.httpHeaders}}")]
    public class WhiteListedHeaders
    {
        /// <summary>
        /// Define the allowed http headers
        /// </summary>
        [DefaultValue("Cookie")]
        public string[] AllowedHttpHeaders { get; set; }

        /// <summary>
        /// Current TCP/IP HTTP headers with a key value pair
        /// </summary>
        public Dictionary<string, string> CurrentHttpHeaders { get; set; }

    }

    /// <summary>
    /// Options class provides additional parameters.
    /// </summary>
    public class Options
    {
        /// <summary>
        /// How many iteration round for decoding of the payloadx.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("2")]
        public int MaxIterations { get; set; }
        
        /// <summary>
        /// Which encoding should be used, default UTF-8.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("UTF-8")]
        public string SourceEncoding { get; set; }
        
        /// <summary>
        /// Which encoding should be used, default UTF-8.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("UTF-8")]
        public string DestinationEncoding { get; set; }
        
        /// <summary>
        /// Should content be base 64 decoded, default UTF-8.
        /// </summary>
        public bool Base64Decode { get; set; }
        
        /// <summary>
        /// Allow null characters.
        /// </summary>
        public bool AllowNullValues { get; set; }
        
        /// <summary>
        /// Allow white space characters.
        /// </summary>
        public bool AllowWhiteSpaces { get; set; }
        
    }
    
}
