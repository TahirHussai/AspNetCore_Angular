using AutoMapper;
using SampleAngular.DTO;
using SampleAngular.Models;

namespace SampleAngular.Configuration
{
    public class AutoMapperConfiguration:Profile
    {
        public AutoMapperConfiguration()
        {
            CreateMap<UserDto, UserPofile>().ReverseMap();
            CreateMap<ProductDTO, Products>().ReverseMap();
            CreateMap<ProductCategoriesDTO, ProductCategory>().ReverseMap();
        }
    }
}
