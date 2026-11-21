FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY ["Directory.Build.props", "./"]
COPY ["VulnTracker.Api/VulnTracker.Api.csproj", "VulnTracker.Api/"]
COPY ["VulnTracker.Api/packages.lock.json", "VulnTracker.Api/"]
RUN dotnet restore "VulnTracker.Api/VulnTracker.Api.csproj" --locked-mode
COPY . .
WORKDIR "/src/VulnTracker.Api"
RUN dotnet publish -c Release --no-restore -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine AS final
WORKDIR /app
USER app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "VulnTracker.Api.dll"]