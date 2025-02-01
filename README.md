# Webex Contact Center Transcript Extraction

## Overview
This repository provides a Python-based solution for extracting chat transcripts from Cisco Webex Contact Center (WxCC). The script authenticates via OAuth, fetches tasks from the Webex API, retrieves chat transcripts, and processes them into an Excel file for further analysis.
For a full code explanation please check: https://3corners.nl/deep-dive-into-webex-contact-center-transcript-extraction-code

## Features
- **OAuth Authentication**: Securely connects to Webex API.
- **Task Retrieval**: Fetches chat tasks within a specified timeframe.
- **Transcript Processing**: Downloads transcripts and exports them to an Excel file.
- **Agent & Queue Mapping**: Associates tasks with agents and queues.
- **Error Handling & Logging**: Detailed logging for debugging.

## Prerequisites
Before running the script, ensure you have:
- Python 3.8 or later installed.
- Webex Developer access with API credentials.
- Required Python libraries (see `requirements.txt`).

## Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/cyberbeuk/wxcc-transcript.git
cd wxcc-transcript
pip install -r requirements.txt
```

## Configuration
Create a config.json file in the root directory with the following:
```{
    "auth_method": "browser",
    "client_id": "<your cliendid></your>",
    "client_secret": "<your clientsecret></your>",
    "org_id": "<your webex org id></your>",
    "redirect_uri": "http://localhost:8089/callback",
    "scope": "spark:kms cloud-contact-center:pod_conv cjp:user spark:people_read cjp:config cjp:config_read cjds:admin_org_read",
    "log_level": "INFO",
    "log_file": "transcript.log",
    "api_urls": {
        "base": "https://webexapis.com/v1",
        "eu": "https://api.wxcc-eu2.cisco.com",
        "auth": "https://webexapis.com/v1/authorize"
    },
    "token_file": "access_token.json",
    "default_queue": "<your queue name></your>",
    "url_expiration": 3600
}
```

Ensure the Webex API app is registered and authorized.

## Running the Script
To start the extraction process:
```bash
python ListTranscripts.py
```
This will:
1. Authenticate with Webex.
2. Retrieve live chat tasks.
3. Fetch and process chat transcripts.
4. Save the output in an Excel file (`transcripts.xlsx`).

## Required Dependencies
The script requires the following Python libraries:
```txt
requests
selenium
webdriver-manager
dotenv
pandas
openpyxl
logging
```
Install them with:
```bash
pip install -r requirements.txt
```

## API Endpoints Used
The script interacts with the following Webex API endpoints:
- **Tasks API**: `GET /v1/tasks` - Retrieves tasks.
- **Captures API**: `POST /v1/captures/query` - Fetches transcript URLs.
- **Agents API**: `GET /v1/agents/activities` - Matches agents with tasks.

## Debugging
If you encounter issues:
- Check `webex_auth.log` for detailed logs.
- Ensure your API credentials are correct.
- Verify that your Webex Developer account has the right permissions.

## Contributions
Feel free to fork this repository, create feature branches, and submit pull requests. Contributions are welcome!

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact
For questions or issues, reach out via GitHub Issues or contact the repository owner.

