#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["Pomelo.Signature/Pomelo.Signature.csproj", "Pomelo.Signature/"]
RUN dotnet restore "Pomelo.Signature/Pomelo.Signature.csproj"
COPY . .
WORKDIR "/src/Pomelo.Signature"
RUN dotnet build "Pomelo.Signature.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Pomelo.Signature.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Pomelo.Signature.dll"]