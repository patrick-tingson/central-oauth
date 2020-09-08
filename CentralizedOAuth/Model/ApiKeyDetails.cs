using System.Collections.Generic;

namespace CentralizedOAuth.Model
{
    public class ApiKeyDetails
    {
        public int GlobalId { get; set; }
        public string Requestor { get; set; }
        public string ApiKey { get; set; }
        public string Role { get; set; }
        public int AccessTokenExpiration { get; set; }
        public List<Rights> Rights { get; set; }
    }
}
