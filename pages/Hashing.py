import streamlit as st
import hashlib

st.set_page_config(
        page_title="Hashing Encryption",
        page_icon="💼",
    )

st.write("# Hashing Functions")

hash_type = st.selectbox("Select Hashing Algorithm", ["MD5", "SHA1", "SHA256", "SHA512"])

if hash_type == "MD5":
    st.write("""
        ### MD5 Hash:
        MD5 (Message Digest Algorithm 5) is a widely used cryptographic hash function that produces a 128-bit (16-byte) hash value. It was designed by Ronald Rivest in 1991 and has been extensively used in various security applications, although its security has been compromised over the years due to vulnerabilities.
        """)
elif hash_type == "SHA1":
    st.write("""
    ### SHA1 Hash:
    SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function that produces a 160-bit (20-byte) hash value. It was designed by the National Security Agency (NSA) and published by the National Institute of Standards and Technology (NIST) in 1993. SHA-1 was widely used for various security applications, but its security has been compromised due to vulnerabilities.
    """)
elif hash_type == "SHA256":
    st.write("""
    ### SHA256 Hash:
    SHA-256 (Secure Hash Algorithm 256) is a cryptographic hash function that belongs to the SHA-2 family of hash functions. It produces a 256-bit (32-byte) hash value, making it more secure than its predecessors SHA-1 and MD5. SHA-256 was designed by the National Security Agency (NSA) and published by the National Institute of Standards and Technology (NIST) in 2001.
    """)
elif hash_type == "SHA512":
    st.write("""
    ### SHA512 Hash:
    SHA-512 (Secure Hash Algorithm 512) is a cryptographic hash function that belongs to the SHA-2 family of hash functions. It produces a 512-bit (64-byte) hash value, making it more secure than its predecessors SHA-1 and MD5, and providing a larger hash size for increased resistance against brute-force attacks. SHA-512 was designed by the National Security Agency (NSA) and published by the National Institute of Standards and Technology (NIST) in 2001.
    """)

st.write("""
    #### Process:
    1. If the input is text, encode the text using UTF-8.
    2. Use the selected hashing algorithm to generate the hash value.
    3. Display the hash value.
    """)

option = st.radio("Choose Input Option", ("Enter Text", "Upload File"))

if option == "Enter Text":
    user_input = st.text_area("Enter TEXT: ")
    if st.button("Encrypt!"):
        if hash_type == "MD5":
            result = hashlib.md5(user_input.encode()).hexdigest()
            st.write("MD5 Hash:", result)
        elif hash_type == "SHA1":
            result = hashlib.sha1(user_input.encode()).hexdigest()
            st.write("SHA1 Hash:", result)
        elif hash_type == "SHA256":
            result = hashlib.sha256(user_input.encode()).hexdigest()
            st.write("SHA256 Hash:", result)
        elif hash_type == "SHA512":
            result = hashlib.sha512(user_input.encode()).hexdigest()
            st.write("SHA512 Hash:", result)

elif option == "Upload File":
    uploaded_file = st.file_uploader("Choose a file", type=None)
    if uploaded_file is not None:
        file_content = uploaded_file.getvalue()
        if hash_type == "MD5":
            result = hashlib.md5(file_content).hexdigest()
            st.write("MD5 Hash:", result)
        elif hash_type == "SHA1":
            result = hashlib.sha1(file_content).hexdigest()
            st.write("SHA1 Hash:", result)
        elif hash_type == "SHA256":
            result = hashlib.sha256(file_content).hexdigest()
            st.write("SHA256 Hash:", result)
        elif hash_type == "SHA512":
            result = hashlib.sha512(file_content).hexdigest()
            st.write("SHA512 Hash:", result)
        else:
            user_input = file_content.decode("utf-8")

