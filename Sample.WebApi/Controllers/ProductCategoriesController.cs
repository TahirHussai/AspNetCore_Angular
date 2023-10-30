using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using SampleAngular.DTO;
using SampleAngular.Models;
using System.Net.NetworkInformation;
using System;
using System.Xml;
using System.Xml.Serialization;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace SampleAngular.Controllers
{
    [Route("api/[controller]")]
    [ApiController]

    public class ProductCategoriesController : ControllerBase
    {
        // GET: api/<ProductsController>
        private readonly App_BlazorDBContext _app_BlazorDBContext;
        private readonly IMapper mapper;
        private readonly ILogger<ProductCategoriesController> logger;
        private IConfiguration _Configuration;
        public ProductCategoriesController(IConfiguration Configuration, App_BlazorDBContext _app_BlazorDBContext, ILogger<ProductCategoriesController> logger, IMapper mapper)
        {
            this.mapper = mapper;
            this.logger = logger;
            this._app_BlazorDBContext = _app_BlazorDBContext;
            _Configuration = Configuration;
        }
        [HttpGet]
        [Route("GetProductsCategories")]
        public async Task<ActionResult<IEnumerable<ProductCategoriesDTO>>> Get()
        {
           
            var ProductCategory = await _app_BlazorDBContext.ProductCategories.ToListAsync();
            return Ok(ProductCategory);
        }

        // GET api/<ProductsController>/5
        [HttpGet("{id}")]

        public async Task<ActionResult<ProductCategoriesDTO>> Get(int id)
        {
            ProductCategoriesDTO products = new ProductCategoriesDTO();
            try
            {
                var product = await _app_BlazorDBContext.ProductCategories.FindAsync(id);
                if (product == null)
                {
                    logger.LogError($"Record Not Found:{nameof(Get)}-ID:{id}");
                    return NotFound();
                }
                products = mapper.Map<ProductCategoriesDTO>(product);
            }
            catch (Exception ex)
            {

                logger.LogError(ex, $"Error performing GetProduct By Id in {nameof(Get)}-ID:{id}");
            }
            return Ok(products);
        }

        // POST api/<ProductsController>
        [HttpPost]
        [Route("AddProductCategories")]
        //[Authorize]
        public async Task<ActionResult<ProductCategoriesDTO>> Post(ProductCategoriesDTO productDTO)
        {
            try
            {
                if (productDTO == null)
                {
                    logger.LogError($"Product Info is required:{nameof(Post)}");
                    return NotFound();
                }
                var product = mapper.Map<ProductCategory>(productDTO);
                await _app_BlazorDBContext.ProductCategories.AddAsync(product);
                await _app_BlazorDBContext.SaveChangesAsync();
                return CreatedAtAction(nameof(Post), new { id = product.CategoryId }, product);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Error performing save Product in {nameof(Post)}");
                return StatusCode(500, ex.ToString());
            }
        }

        // PUT api/<ProductsController>/5
        [HttpPut("{id}")]

        [Authorize(Roles = "Administrator")]
        public async Task<ActionResult> Put(int id, ProductCategoriesDTO productDTO)
        {
            if (id <= 0)
            {
                logger.LogError($"Update Id is Invalid in :{nameof(Put)}-ID:{id}");
                return BadRequest();
            }

            var product = await _app_BlazorDBContext.ProductCategories.FindAsync(id);

            if (product == null)
            {
                logger.LogError($"Record Not Found:{nameof(Put)}-ID:{id}");
                return NotFound();
            }
            mapper.Map(productDTO, product);
            _app_BlazorDBContext.Entry(product).State = EntityState.Modified;
            await _app_BlazorDBContext.SaveChangesAsync();
            return NoContent();
        }

        // DELETE api/<ProductsController>/5
        [HttpDelete("{id}")]
        //[Authorize(Roles = "Administrator")]
        public async Task<ActionResult> Delete(int id)
        {
            try
            {
                var product = await _app_BlazorDBContext.ProductCategories.FindAsync(id);
                if (product == null)
                {
                    logger.LogError($"Record Not Found:{nameof(Delete)}-ID:{id}");
                    return NotFound();
                }
                _app_BlazorDBContext.ProductCategories.Remove(product);
                await _app_BlazorDBContext.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Error performing Delete Product in {nameof(Delete)}");

            }
            return Ok();
        }
     
    }
}
