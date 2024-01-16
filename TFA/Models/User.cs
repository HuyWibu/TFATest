using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace TFA.Models
{
    public class User
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
    }

}
