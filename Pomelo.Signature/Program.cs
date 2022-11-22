using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseSwagger();
app.UseSwaggerUI();

// Setup the two endpoints that Pomelo will hit in order to process card
// transactions:

string endpoint = string.Empty;
string timestamp = string.Empty;
string signature = string.Empty;
string apiKey = string.Empty;

app.MapPost("/transactions/authorizations", async (IHttpContextAccessor _) => await Authorizations(_));

app.MapPost("/transactions/adjustments", async (IHttpContextAccessor _) => await Adjustment(_));


async Task Adjustment(IHttpContextAccessor _)
{
    if (!(await CheckSignature(_)))
    {
        Console.WriteLine("Invalid signature, aborting");
        _.HttpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;
        await _.HttpContext.Response.WriteAsync("");
    }

    // do your logic

    Console.WriteLine("Adjustment processed");


    // Marshal object to bytes (alternatively to string and then to bytes). It's
    // important to sign the exact same bytes that are written to the response
    // body.
    // Be careful with frameworks that allow you to return objects directly,
    // because their json marshalling might be different from yours. In that
    // case we recommend using a filter/interceptor/middleware to access the
    // raw response body

    _.HttpContext?.Response?.Headers.Clear();

    var signatureResponse = SignResponse(_); // sign response first so headers are written before body
    _.HttpContext?.Response.Headers?.Add("X-Signature", string.Concat("hmac-sha256 ", signatureResponse));
    _.HttpContext?.Response.Headers?.Add("X-Timestamp", $"{timestamp}");
    _.HttpContext?.Response.Headers?.Add("X-Endpoint", endpoint);
    _.HttpContext?.Response.Headers?.Add("Content-Type", "application/json");
    _.HttpContext.Response.StatusCode = StatusCodes.Status200OK;

    await _.HttpContext.Response.WriteAsync("");
}


async Task Authorizations(IHttpContextAccessor _)
{
    if (!(await CheckSignature(_)))
    {
        Console.WriteLine("Invalid signature, aborting");
        _.HttpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;
        await _.HttpContext.Response.WriteAsync("");
    }

    // do your logic

    Console.WriteLine("Authorization processed");

    var response = new
    {
        Status = "APPROVED",
        StatusDetail = "APPROVED",
        Message = "OK"
    };

    // Marshal object to bytes (alternatively to string and then to bytes). It's
    // important to sign the exact same bytes that are written to the response
    // body.
    // Be careful with frameworks that allow you to return objects directly,
    // because their json marshalling might be different from yours. In that
    // case we recommend using a filter/interceptor/middleware to access the
    // raw response body
    var bodyJson = JsonSerializer.Serialize(response);

    _.HttpContext?.Response?.Headers.Clear();

    var signatureResponse = SignResponse(_, bodyJson); // sign response first so headers are written before body
    _.HttpContext?.Response.Headers?.Add("X-Signature", string.Concat("hmac-sha256 ", signatureResponse));
    _.HttpContext?.Response.Headers?.Add("X-Timestamp", $"{timestamp}");
    _.HttpContext?.Response.Headers?.Add("X-Endpoint", endpoint);
    _.HttpContext?.Response.Headers?.Add("Content-Type", "application/json");
    _.HttpContext.Response.StatusCode = StatusCodes.Status200OK;

    await _.HttpContext.Response.WriteAsync(bodyJson);

}


// checkSignature does all the signature validations that you need to implement
// to make sure only Pomelo has signed this request and not an attacker. A
// signature mismatch should abort the http request or return Forbidden
async Task<bool> CheckSignature(IHttpContextAccessor _)
{

    endpoint = _.HttpContext?.Request?.Headers.FirstOrDefault(f => f.Key == "x-endpoint").Value;

    timestamp = _.HttpContext?.Request?.Headers.FirstOrDefault(f => f.Key == "x-timestamp").Value;

    signature = _.HttpContext?.Request?.Headers.FirstOrDefault(f => f.Key == "x-signature").Value;

    apiKey = _.HttpContext?.Request?.Headers.FirstOrDefault(f => f.Key == "x-api-key").Value;

    if (endpoint is null)
        return false;

    if (timestamp is null)
        return false;

    if (signature is null)
        return false;

    if (apiKey is null)
        return false;

    // pomelo sends the algorithm + the signature in the x-signature header, separated by a space
    // ex:
    // 		x-signature:hmac-sha256 whk5mllmd+zjbkedga9lyzvusnsdkwj94qm3exy6vk8=

    if (signature.StartsWith("hmac-sha256 "))
        signature = signature.Replace("hmac-sha256 ", "");
    else
    {
        Console.WriteLine("unsupported signature algorithm, expecting hmac - sha256, got ${ signature}");
        return false;
    }
    // important to read the raw body directly from the request as bytes, prior
    // to any json object deserialization which are framework-specific and can
    // change the string representation

    string rawBody = await GetRawBody(_.HttpContext?.Request.Body);

    string secret = GetApiSecret(apiKey);

    string inputstring = string.Concat(timestamp, endpoint, rawBody);

    //// construct a new hasher and hash timestamp + endpoint + body without any
    //// separators nor any decoding
    var hashResultBytes = new HMACSHA256(System.Convert.FromBase64String(secret))
                            .ComputeHash(new UTF8Encoding().GetBytes(inputstring));

    //// compare signatures using a cryptographically secure function
    //// for that you normally need the signature bytes, so decode from base64
    byte[] signatureBytes = Convert.FromBase64String(signature);

    bool signaturesMatch = signatureBytes.SequenceEqual(hashResultBytes);

    if (!signaturesMatch)
    {
        Console.WriteLine($"Signature mismatch.Received {signature}, calculated {System.Convert.ToBase64String(hashResultBytes)}");
        return false;
    }

    return true;

}


string GetApiSecret(string apiKey)
{
    // Change to search in settings
    var keys = new Dictionary<string, string>{
        {"sKQq91g4ctRkLElI86vMeRNIPbhUc2qyEWxgbt6CGP8=","hByKl5U+zzpMibm7MiEnjEsnBHC4ntATnEhjzKRw2fw="}
    };

    return keys.FirstOrDefault(k => k.Key == apiKey).Value ?? string.Empty;
}


async Task<string> GetRawBody(Stream? stream)
{
    if (stream is null) return string.Empty;

    System.IO.StreamReader sr = new System.IO.StreamReader(stream);

    return await sr.ReadToEndAsync();

}


string SignResponse(IHttpContextAccessor _, string? bodyJson = null)
{
    string content = string.Empty;
    if (string.IsNullOrEmpty(bodyJson))
    {
        content = String.Concat(timestamp, endpoint);
    }
    else
    {
        content = String.Concat(timestamp, endpoint, bodyJson);
    }

    byte[] keyByte = System.Convert.FromBase64String(apiKey);

    byte[] messageBytes = new UTF8Encoding().GetBytes(content);

    byte[] hashmessage = new HMACSHA256(keyByte).ComputeHash(messageBytes);

    return Convert.ToBase64String(hashmessage);

}


app.Run();