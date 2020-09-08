using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CentralizedOAuth.Model
{
    public class ClientCredentials
    {
        public string Id { get; set; }
        public string Rev { get; set; }
        public string ClientId { get; set; }
        public string ClientName { get; set; }
        public List<ApiKeyDetails> ApiKeys { get; set; }
        public DateTime Created { get; set; }
        public DateTime ActiveDate { get; set; }
        public string InactiveDate { get; set; }
        public bool Active { get; set; }
    }
}
