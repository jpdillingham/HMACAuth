namespace HMACAuth.Security
{
    using Microsoft.AspNetCore.Authentication;
    using System;

    public class HmacAuthenticationOptions : AuthenticationSchemeOptions
    {
        public HmacAuthenticationOptions()
        {
        }

        public bool ValidateCIDR { get; set; } = true;
        public string DateTimeFormat { get; set; } = "yyyy-MM-ddTHH:mm:ss.fffK";
        public TimeSpan ClockDrift { get; set; } = new TimeSpan(hours: 0, minutes: 5, seconds: 0);
    }
}
