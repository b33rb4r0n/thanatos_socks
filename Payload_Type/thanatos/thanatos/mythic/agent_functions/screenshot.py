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
        Process the agent response from screenshot command (Apollo's approach)
        """
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        
        try:
            # FIX: Handle both string and JSON responses from agent
            if isinstance(response, dict) and "output" in response:
                # Agent returned JSON format: {"status": "success", "output": "..."}
                response_text = str(response["output"])
            else:
                # Agent returned plain string (our fixed version)
                response_text = str(response)
            
            if response_text:
                # Check if the response contains our special format for screenshot (Apollo's approach)
                if response_text.startswith("screenshot_captured:"):
                    # Parse the response: format is "screenshot_captured:file_path:file_size:filename:type"
                    parts = response_text.split(":")
                    if len(parts) >= 4:
                        file_path = parts[1]
                        file_size = parts[2]
                        filename = parts[3]
                        file_type = parts[4] if len(parts) > 4 else "screenshot"
                        
                        # Create a download task for the screenshot automatically (Apollo's approach)
                        try:
                            download_task = await SendMythicRPCTaskCreate(MythicRPCTaskCreateMessage(
                                TaskID=task.Task.ID,
                                CommandName="download",
                                Parameters=json.dumps({"file": file_path}),
                                CallbackID=task.Callback.ID
                            ))
                            
                            if download_task.Success:
                                # Return a response that the browser script can use
                                response_data = {
                                    "file_id": download_task.response.get("file_id", "unknown"),
                                    "filename": filename,
                                    "file_size": file_size,
                                    "message": f"Screenshot captured successfully! File: {filename} ({file_size} bytes)"
                                }
                                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                                    TaskID=task.Task.ID,
                                    Response=json.dumps(response_data).encode()
                                ))
                            else:
                                # Fallback: manual download instructions
                                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                                    TaskID=task.Task.ID,
                                    Response=f"Screenshot captured: {filename} ({file_size} bytes)\n\nTo download manually, use: download {file_path}".encode()
                                ))
                        except Exception as e:
                            # Fallback on error
                            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                                TaskID=task.Task.ID,
                                Response=f"Screenshot captured: {filename} ({file_size} bytes)\n\nTo download manually, use: download {file_path}\nError: {str(e)}".encode()
                            ))
                    else:
                        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                            TaskID=task.Task.ID,
                            Response=f"Screenshot captured but failed to parse file information. Raw response: {response_text}".encode()
                        ))
                elif response_text.startswith("error:"):
                    # Handle error responses from agent
                    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                        TaskID=task.Task.ID,
                        Response=response_text.encode()
                    ))
                else:
                    # Regular response (unexpected format)
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