MAIN_PROJECT = ./AdvancedSystems.Security
TEST_PROJECT = ./AdvancedSystems.Security.Tests

import-certificate:
	# password certificate authority
	dotnet certificate-tool add --file ./development/AdvancedSystems-CA.pfx \
		--store-name My \
		--store-location CurrentUser \
		--password $(password);

	# password certificate
	# TODO: read values from appsettings.json
	dotnet certificate-tool add --file ./development/AdvancedSystems-PasswordCertificate.pem \
		--store-name My \
    	--store-location CurrentUser;

install: import-certificate
	# main project
	dotnet restore --configfile nuget.config
	dotnet tool restore --configfile nuget.config
	dotnet husky install

	# unit test project
	dotnet user-secrets init --project $(TEST_PROJECT)
	dotnet user-secrets set CertificatePassword $(password) --project $(TEST_PROJECT)

build: 
	dotnet build $(MAIN_PROJECT) --configuration $(configuration) --no-restore /warnAsError

test: build
	dotnet test $(TEST_PROJECT) --configuration $(configuration) --verbosity normal

documentation:
	dotnet tool restore --configfile nuget.config

	if [ "$(serve)" = "true" ]; then \
		dotnet docfx ./docs/docfx.json --serve --open-browser; \
	else \
		dotnet docfx ./docs/docfx.json; \
	fi

clean:
	dotnet clean
	dotnet clean --configuration Release
	@clear

$(V).SILENT: