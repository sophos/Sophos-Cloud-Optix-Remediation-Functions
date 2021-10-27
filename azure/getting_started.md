## Getting Started with Azure Function
### Last updated: March 8th 2021

#### Project Structure
The main project folder <azure> can contain the following files:

* **local.settings.json** - Used to store app settings and connection strings when running locally. This file doesn't get published to Azure. To learn more, see [local.settings.file](https://aka.ms/azure-functions/python/local-settings).
* **requirements.txt** - Contains the list of Python packages the system installs when publishing to Azure.
* **host.json** - Contains global configuration options that affect all functions in a function app. This file does get published to Azure. Not all options are supported when running locally. To learn more, see [host.json](https://aka.ms/azure-functions/python/host.json).
* **.vscode/** -  Contains store VSCode configuration. To learn more, see [VSCode setting](https://aka.ms/azure-functions/python/vscode-getting-started).
* **webhook/** -  Have all the azure remediation functions

Each function has its own code file and binding configuration file ([**function.json**](https://aka.ms/azure-functions/python/function.json)).

#### Publishing your function app to Azure 

For more information on deployment options for Azure Functions, please visit this [guide](https://docs.microsoft.com/en-us/azure/azure-functions/create-first-function-vs-code-python#publish-the-project-to-azure).

#### Next Steps

* To learn more about developing Azure Functions, please visit [Azure Functions Developer Guide](https://aka.ms/azure-functions/python/developer-guide).

* To learn more specific guidance on developing Azure Functions with Python, please visit [Azure Functions Developer Python Guide](https://aka.ms/azure-functions/python/python-developer-guide).