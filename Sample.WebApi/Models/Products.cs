﻿using System.ComponentModel.DataAnnotations;

namespace SampleAngular.Models
{
    public class Products
    {
        [Key]
        public int ProductId { get; set; }
        public string ProductName { get; set; }
        public decimal ProductPrice { get; set; }
        public string ProductCategory { get; set; }
        public string ProductImage { get; set; }
        public string ProductDescription { get; set; }
        public DateTime EntryDate { get; set; }
    }
}
