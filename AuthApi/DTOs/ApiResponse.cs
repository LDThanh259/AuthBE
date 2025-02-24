namespace AuthApi.DTOs
{
    public class ApiResponse<T>
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public T Data { get; set; }
        public IEnumerable<string> Errors { get; set; }

        public static ApiResponse<T> SuccessResult(T data, string message = null) => new()
        {
            Success = true,
            Data = data,
            Message = message
        };

        public static ApiResponse<T> ErrorResult(string message, IEnumerable<string> errors = null) => new()
        {
            Success = false,
            Message = message,
            Errors = errors
        };
    }
}
