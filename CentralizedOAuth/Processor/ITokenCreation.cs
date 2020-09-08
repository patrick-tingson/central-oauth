using CentralizedOAuth.Model;

namespace CentralizedOAuth.Processor
{
    public interface ITokenCreation
    {
        AccessTokenResult ValidateCredential();
    }
}