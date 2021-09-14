using System;
using System.Collections.Generic;
using NUnit.Framework;
using System.Threading;

namespace Frends.Community.SecurityThreatDiagnostics.Tests
{
    [TestFixture]
    class TestClass
    {
        Validation validation = new Validation();
        ValidationAttributes validationAttributes = new ValidationAttributes();
        Options options = new Options();
        
        [SetUp]
        public void SetUp()
        {
            options.SourceEncoding = "ISO-8859-1";
            options.DestinationEncoding = "ISO-8859-7";
            options.Base64Decode = true;
        }

        [Test]
        public void GivenValidTextWhenChallengingValidationThenSecurityThreatDiagnosticsMustRaiseExceptionDueToFoundInjection()
        {
            string validXml = "This is a valid content.";
            validation.Payload = validXml;
            options.MaxIterations = 2;
            SecurityThreatDiagnosticsResult result = SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, CancellationToken.None);
            Assert.IsTrue(result.IsValid);
        }
        
        [Test]
        public void GivenXXEInjectedXMLWhenChallengingValidationOfTheXMLThenSecurityThreatDiagnosticsMustNotRaiseException()
        {
            string validXml = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>";
            validation.Payload = validXml;    
            options.MaxIterations = 2;
            Assert.Throws<ApplicationException>(() => SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, CancellationToken.None));
        }
        
        [Test]
        public void GivenScriptInjectedXMLWhenChallengingValidationThenSecurityThreatDiagnosticsMustRaiseExceptionDueToInjectedXML()
        {
            string invalidXml = "<xml><entity><script>function xss() { alert('injection'); } xss();</script></entity></xml>";
            validation.Payload = invalidXml;
            options.MaxIterations = 2;
            Assert.Throws<ApplicationException>(() => SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, CancellationToken.None) );
        }
        
        [Test]
        public void GivenScriptInjectedXMLWithDoubleQuatesWhenChallengingValidationThenSecurityThreatDiagnosticsMustRaiseExceptionDueToInjectedXML()
        {
            string invalidXml = "<xml><entity><script>function xss() { alert(\"injection\"); } xss();</script></entity></xml>";
            validation.Payload = invalidXml;
            options.MaxIterations = 2;
            Assert.Throws<ApplicationException>(() => SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, CancellationToken.None));
        }
        
        [Test]
        public void GivenXSScriptAttackScriptAsAnAttributeWhenChallengingValidationThenSecurityThreatDiagnosticsMustRaiseExceptionDueToInjectedValue()
        {
            string invalidXml = "function xss() { alert('injection'); } xss();";
            validation.Payload = invalidXml;
            options.MaxIterations = 2;
            Assert.Throws<ApplicationException>(() =>  SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, CancellationToken.None) );
        }
        
        [Test]
        public void GivenDoubleEncodedUrlInjectionInURIFormatWhenChallengingValidationThenSecurityThreatDiagnosticsMustRaiseExceptionDueToDoubleEncodedURI()
        {
            string unsecureUrl = "http://victim/cgi/%252E%252E%252F%252E%252E%252Fwinnt/system32/cmd.exe?/c+dir+c:\";";
            validation.Payload = unsecureUrl;
            options.MaxIterations = 2;
            Assert.Throws<ApplicationException>(() =>  SecurityThreatDiagnostics.ChallengeUrlEncoding(validation, options, CancellationToken.None) );
        }

        [Test]
        public void GivenUnknownCharacterWhenChallengingEncodingThenSecurityThreatDiagnosticsMustConvertToKnownCharacterSetEncoding()
        {
            string unknownCharacters = "ዩኒኮድ ወረጘ የጝ00F800F8يونِكودö'>>B$ôI#€%&/()?@∂öيونِكود";
            validation.Payload = unknownCharacters;
            Assert.DoesNotThrow(() => SecurityThreatDiagnostics.ChallengeCharacterSetEncoding(validation.Payload, options));
        }

        [Test]
        public void GivenUrlInjectionInURIFormatWhenChallengingValidationThenSecurityThreatDiagnosticsMustRaiseExceptionDueToFoundSQLInjection()
        {
            string unsecureUrl = "select * from Customers;`insert into";
            validation.Payload = unsecureUrl;
            options.MaxIterations = 2;
            Assert.Throws<ApplicationException>(() => SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, CancellationToken.None));
        }
        
        [Test]
        public void GivenInjectedHeaderInWhenChallengingHeadersForValidationThenSecurityThreatDiagnosticsMustRaiseExceptionDueToInjectedHeaderValue()
        {
            WhiteListedHeaders whiteListedHeaders = new WhiteListedHeaders();
            whiteListedHeaders.AllowedHttpHeaders = new [] {"Authorization"};
            whiteListedHeaders.CurrentHttpHeaders = new Dictionary<string, string>();
            whiteListedHeaders.CurrentHttpHeaders.Add("Authorization: ", "Bearer <script>function attack(){ alert(\"i created XSS\"); } attack();</script>"); 
            Assert.Throws<ApplicationException>(() => SecurityThreatDiagnostics.ChallengeSecurityHeaders(whiteListedHeaders, options, CancellationToken.None));
        }
        
        private static String StaticHeader = "Authorization"; 
        
        [Test]
        //[Ignore("Not yet implemented")]
        public void GivenStandardHeaderInWhenChallengingHeadersForValidationThenSecurityThreatDiagnosticsMustByPassRelevantHeaders()
        {
            WhiteListedHeaders whiteListedHeaders = new WhiteListedHeaders();
            whiteListedHeaders.AllowedHttpHeaders = new [] {StaticHeader};
            whiteListedHeaders.CurrentHttpHeaders = new Dictionary<string, string>();
            whiteListedHeaders.CurrentHttpHeaders.Add("Authorization: ", "Bearer hashme"); 
            SecurityThreatDiagnosticsResult result = SecurityThreatDiagnostics.ChallengeSecurityHeaders(whiteListedHeaders, options, CancellationToken.None);
            Assert.IsTrue(result.IsValid);
        }
        
        [Test]
        [Ignore("Not yet implemented")]
        public void GivenInvalidAttributesWhenChallengingPayloadAttributesForValidationThenSecurityThreatDiagnosticsMustRaiseExceptionDueToInjectedAttributss()
        {
            string invalidAttribute1 = "<script>function xss() { alert('injection'); } xss();</script>";
            string invalidAttribute2 = "<script>function xss() { alert('injection'); } xss();</script>";
            Dictionary<string, bool> attributes = new Dictionary<string, bool>();
            attributes.Add(invalidAttribute1, true);
            attributes.Add(invalidAttribute2, true);
            validationAttributes.Attribute = attributes;
           
            Assert.Throws<ApplicationException>(() => SecurityThreatDiagnostics.ChallengeAttributesAgainstSecurityThreats(validationAttributes, options, CancellationToken.None));
        }
        
        [Test]
        public void GivenAttackVectorWithMultipleAttributesWhenChallengingPayloadAttributesForValidationThenSecurityThreatDiagnosticsMustRaiseExceptionDueToFoundAttackPattern()
        {
            string invalidAttribute1 = "{ payload : {Name" + ":" + "%27 %3E%3E";
            string invalidAttribute2 = "Address" + ":" + "%3Cscript%3E function attack() %7B alert(%27xss%27)%3B %7D";
            string invalidAttribute3 = "Mobile"+ ":" + "attack()%3B %3C%2Fscript%3E}}";
            string parallel = invalidAttribute1 + invalidAttribute2 + invalidAttribute3;
            Dictionary<string, bool> attributes = new Dictionary<string, bool>();
            attributes.Add(invalidAttribute1, true);
            attributes.Add(invalidAttribute2, true);
            attributes.Add(invalidAttribute3, true);
            validationAttributes.Attribute = attributes;
           
            Assert.Throws<ApplicationException>(() => SecurityThreatDiagnostics.ChallengeAttributesAgainstSecurityThreats(validationAttributes, options, CancellationToken.None));
        }
        
        [Test]
        public void GivenAttackVectorWithCharacterEscapedAttributesWhenChallengingPayloadAttributesForValidationThenSecurityThreatDiagnosticsMustRaiseExceptionDueToInvalidException()
        {
            string invalidAttribute1 = "{payload : {Name" + ":" + "PHNjcmlwdD5mdW5jdGlvbiBhdHRhY2sgKCkge2FsZXJ0KCd4c3MnKTt9YXR0YWNrKCk7PC9zY3JpcHQ+";
            string invalidAttribute2 = "Address : test";
            string invalidAttribute3 = "Mobile +358123456789 }}' >> mysqldump --all-databases > dump.sql";
            string parallel = invalidAttribute1 + invalidAttribute2 + invalidAttribute3;
            Dictionary<string, bool> attributes = new Dictionary<string, bool>();
            attributes.Add(invalidAttribute1, true);
            attributes.Add(invalidAttribute2, true);
            attributes.Add(invalidAttribute3, true); 
            attributes.Add(parallel, true);
            validationAttributes.Attribute = attributes;
            options.Base64Decode = true;
            Assert.Throws<ApplicationException>(() => SecurityThreatDiagnostics.ChallengeAttributesAgainstSecurityThreats(validationAttributes, options, CancellationToken.None));
        }

        [Test]
        public void GivenAllowedIPAddressWhenChallengingIPForValidationThenSecurityThreatDiagnosticsMustNotRaiseExceptionDueToAllowedIPs() {
            AllowedIPAddresses allowedIpAddresses = new AllowedIPAddresses();
            //IPV4 and IPV6
            string[] allowedIPAddressesRegex =
            {
                "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"
            };
            
            string[] denyBroadcastIPAddressesRegex =                                                        
            {                                                                                         
                "255.255.255.255"
            };                                                                                        
            
            allowedIpAddresses.WhiteListedIpAddress = allowedIPAddressesRegex;
            allowedIpAddresses.BlackListedIpAddresses = denyBroadcastIPAddressesRegex;
            allowedIpAddresses.Host = "127.0.0.1";
            Assert.DoesNotThrow(() => SecurityThreatDiagnostics.ChallengeIPAddresses(allowedIpAddresses, CancellationToken.None));
        }
    }
}
