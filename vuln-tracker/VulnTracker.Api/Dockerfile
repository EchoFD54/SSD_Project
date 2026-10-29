FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY ["VulnTracker.Api/VulnTracker.Api.csproj", "VulnTracker.Api/"]
RUN dotnet restore "VulnTracker.Api/VulnTracker.Api.csproj"
COPY . .
WORKDIR "/src/VulnTracker.Api"
RUN dotnet publish -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
USER app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "VulnTracker.Api.dll"]