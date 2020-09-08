using System.Collections.Generic;

namespace CentralizedOAuth.Model
{
    public class Rights
    {
        public string method { get; set; }
        public List<string> actions { get; set; } 
    }
}
