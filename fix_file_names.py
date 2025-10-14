import os
import re

# This program is to change the name of the public class in java files to be same as the file name with replacing
# the non-alphanumeric characters with underscore to avoid compilation errors.

# Function to clean the class name
def clean_class_name(file_name):
    # Remove the file extension
    base_name = os.path.splitext(file_name)[0]
    # Remove non-alphanumeric characters and capitalize
    clean_name = re.sub(r'[^0-9a-zA-Z]', '_', base_name)
    return clean_name

# Directory containing the Java files
# directory = "C:/sourceCode/PhD/code-llm-evaluation-dataset/dataset/output/CLAUDE_claude-3-5-sonnet-20240620"  # Update this path
# directory = "C:/sourceCode/PhD/code-llm-evaluation-dataset/dataset/test"  # Update this path
# directory = "C:/sourceCode/PhD/code-llm-evaluation-dataset/dataset/output/GEMINI_gemini-1.5-pro-001"  # Update this path
# directory = "C:/sourceCode/PhD/code-llm-evaluation-dataset/dataset/output/MISTRAL_codestral-latest"  # Update this path
# directory = "C:/sourceCode/PhD/code-llm-evaluation-dataset/dataset/output/OPENAI_gpt-4o"  # Update this path
directory = "C:/sourceCode/PhD/llm-generated-code-python/output/llama3"  # Update this path

# Process each Java file in the directory
for file_name in os.listdir(directory):
    if file_name.endswith('.py'):
        file_path = os.path.join(directory, file_name)
        new_class_name = clean_class_name(file_name)
        # os.mkdir(os.path.join(directory, f"{new_class_name}"))
        os.rename(os.path.join(directory, file_name), os.path.join(f"{directory}", f"{new_class_name}.py"))
