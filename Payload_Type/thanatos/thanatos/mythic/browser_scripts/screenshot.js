function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }
    if(responses.length > 0){
        let responseArr = [];
        for(let i = 0; i < responses.length; i++){
            try{
                // Handle both string responses and JSON objects
                let responseData = responses[i];
                
                // If it's a string, try to parse it as JSON
                if (typeof responseData === 'string') {
                    try {
                        responseData = JSON.parse(responseData);
                    } catch (e) {
                        // If it's not JSON, skip this response
                        console.log("Not JSON, skipping:", responseData);
                        continue;
                    }
                }
                
                // Check if this is a media response with file_id
                if (responseData && responseData.hasOwnProperty('file_id')) {
                    responseArr.push({
                        "agent_file_id": responseData['file_id'],
                        "filename": responseData['filename'] || "screenshot.bmp", // Use actual filename or default
                    });
                }
            } catch(error) {
                console.log("Error processing response:", error);
            }
        }
        
        if (responseArr.length > 0) {
            return {"media": responseArr};
        } else {
            // If no media found, show the responses as plaintext
            const combined = responses.reduce( (prev, cur) => {
                return prev + (typeof cur === 'string' ? cur : JSON.stringify(cur));
            }, "");
            return {"plaintext": combined || "No media to display"};
        }
    } else {
        return {"plaintext": "No data to display..."}
    }
}