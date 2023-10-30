using System.ComponentModel.DataAnnotations;

namespace SampleAngular.Models
{
    public class OrderDetails
    {
        [Key]
        public int OrderId { get; set; }
        public string UserId { get; set; }
        public int ProductId { get; set; }
        public string PaymentTransactionId { get; set; }
        public decimal TotalAmount { get; set; }
        public DateTime OrderDate { get; set; }
        public string OrderStatus { get; set; }
    }
  

}
