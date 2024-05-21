# Copyright (c) Streamlit Inc. (2018-2022) Snowflake Inc. (2022)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import streamlit as st
from streamlit.logger import get_logger

LOGGER = get_logger(__name__)


def run():
    st.set_page_config(
        page_title="Final Project in Cryptography",
        page_icon="🔐",
    )

    st.markdown("<h1 style='text-align: center;'>Final Project In<br>Applied Cryptography - CSAC 329</h1>", unsafe_allow_html=True)
    st.divider()

    st.markdown("<h3 style='font-weight:bold;'>By: Group 14</h3>", unsafe_allow_html=True)
    st.write("Espion, Paolo L.")
    st.write("Albonial, Jeland O.")
    st.write("Relles, Adrian James.")
    st.write("BSCS 3B")


if __name__ == "__main__":
    run()
