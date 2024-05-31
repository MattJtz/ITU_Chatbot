import streamlit as st
import os
import openai
from openai import OpenAI
import streamlit.components.v1 as components
from vulnerability_scanner import analyze_code  # Import the analyze_code function

client = OpenAI(api_key=st.secrets["OPENAI_API_KEY"])

def check_code_with_openai(file_content):
    try:
        response = openai.Completion.create(
            engine="davinci-codex",
            prompt=f"Check if the following code adheres to OWASP guidelines. Identify errors and suggest fixes. Provide the line number for each error:\n\n{file_content}\n\n",
            max_tokens=500
        )
        return response.choices[0].text.strip()
    except Exception as e:
        return f"Error analyzing code: {e}"

def display_folder_tree(folder_path, depth=0):
    try:
        contents = os.listdir(folder_path)
        for content in contents:
            content_path = os.path.join(folder_path, content)
            indent = "---" * depth
            if os.path.isdir(content_path):
                st.markdown(f"{indent} 📁 **{content}**")
                display_folder_tree(content_path, depth + 1)
            else:
                st.markdown(f"{indent} 📄 {content}")
    except Exception as e:
        st.error(f"Error accessing folder: {e}")

def annotate_code(file_content, errors):
    annotated_code = []
    lines = file_content.split('\n')
    error_lines = {int(e.split(':')[0]): e.split(':')[1].strip() for e in errors if ':' in e and e.split(':')[0].isdigit()}
    
    for i, line in enumerate(lines):
        if i + 1 in error_lines:
            annotated_code.append(f"{line}  # Error: {error_lines[i + 1]}")
        else:
            annotated_code.append(line)
    
    return '\n'.join(annotated_code)

def main():
    st.title("Folder Tree Viewer and Code Checker")

    # State management
    if "folder_path" not in st.session_state:
        st.session_state.folder_path = ""
    if "uploaded_file" not in st.session_state:
        st.session_state.uploaded_file = None
    if "code_input" not in st.session_state:
        st.session_state.code_input = ""

    # Option to manually enter folder path
    folder_path = st.text_input("Enter the folder path:", st.session_state.folder_path)

    # Option to drag and drop a file from the folder
    uploaded_file = st.file_uploader("Or drag and drop a file from the folder", type=None, key="file_uploader")

    if uploaded_file is not None:
        folder_path = os.path.dirname(uploaded_file.name)
        st.session_state.folder_path = folder_path
        st.session_state.uploaded_file = uploaded_file
        st.write(f"Selected folder: {folder_path}")

     # Move the reset button to the end of the page
    if st.button("Reset"):
        st.session_state.folder_path = ""
        st.session_state.uploaded_file = None
        st.experimental_rerun()
        
    if st.button("Show Folder Tree"):
        if folder_path:
            if os.path.exists(folder_path) and os.path.isdir(folder_path):
                st.session_state.folder_path = folder_path
                display_folder_tree(folder_path)
            else:
                st.error("Invalid folder path. Please enter a valid folder path.")
        else:
            st.error("Please enter a folder path or upload a file.")

    if st.button("Check Code for OWASP Compliance"):
        if folder_path:
            if os.path.exists(folder_path) and os.path.isdir(folder_path):
                st.write("Checking code files for OWASP compliance...")
                file_paths = []
                for root, dirs, files in os.walk(folder_path):
                    for file in files:
                        file_paths.append(os.path.join(root, file))

                progress_bar = st.progress(0)
                for i, file_path in enumerate(file_paths):
                    st.write(f"Checking {file_path}...")
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            file_content = f.read()
                            result = check_code_with_openai(file_content)
                            
                            if "Error analyzing code" in result:
                                st.write(result)
                            else:
                                # Extract errors and suggestions
                                errors = result.split('\n')
                                annotated_code = annotate_code(file_content, errors)
                                
                                st.markdown(f"### {file_path}")
                                st.code(annotated_code, language='python')
                                st.markdown("### Errors and Suggestions")
                                st.write(result)
                    except Exception as e:
                        st.write(f"Error reading file {file_path}: {e}")
                    progress_bar.progress((i + 1) / len(file_paths))
            else:
                st.error("Invalid folder path. Please enter a valid folder path.")
        else:
            st.error("Please enter a folder path or upload a file.")

    st.markdown("### Code Vulnerability Scanner")
    code_input = st.text_area("Paste your code here:", height=200, value=st.session_state.code_input, key="code_input")

    if st.button("Analyze Code for Vulnerabilities"):
        if st.session_state.code_input:
            analysis_results = analyze_code(st.session_state.code_input)
            st.markdown("### Vulnerability Analysis Results")
            for result in analysis_results:
                st.markdown(f"**{result['vulnerability']}** at line {result['line']}")
                st.code(result['snippet'], language='python')
                st.markdown(f"**Recommendation:** {result['recommendation']}")
        else:
            st.error("Please paste code to analyze.")

if __name__ == "__main__":
    main()