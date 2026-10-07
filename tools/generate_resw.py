import re
import xml.sax.saxutils as saxutils
from pathlib import Path

def generate_resw():
    loc_file = Path("apps/windows/Fetih.Desktop/Services/Localization.cs")
    content = loc_file.read_text(encoding="utf-8")

    # Match: ["key"] = new("Tr", "En"),
    # Handling multi-line strings as well
    pattern = re.compile(
        r'\["([^"]+)"\]\s*=\s*new\(\s*'
        r'((?:"(?:[^"\\]|\\.)*"\s*(?:\+\s*)?)+),\s*'
        r'((?:"(?:[^"\\]|\\.)*"\s*(?:\+\s*)?)+)\)',
        re.DOTALL
    )

    def clean_str(raw):
        # Concatenate parts if split by +
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', raw)
        combined = "".join(parts)
        return (
            combined.replace('\\"', '"')
            .replace('\\\\', '\\')
            .replace('\\n', '\n')
            .replace('\\r', '\r')
            .replace('\\t', '\t')
        )

    pairs = {}
    for m in pattern.finditer(content):
        key = m.group(1)
        tr = clean_str(m.group(2))
        en = clean_str(m.group(3))
        pairs[key] = (tr, en)

    print(f"Extracted {len(pairs)} localization keys from Localization.cs")

    # Additional standard keys / x:Uid aliases
    aliases = {
        "Chat_NewChat.Content": ("chat.new_chat", "Content"),
        "Chat_PromptBox.PlaceholderText": ("chat.prompt_placeholder", "PlaceholderText"),
        "Chat_SendButton.Content": ("chat.send", "Content"),
        "Chat_StopButton.Content": ("chat.stop", "Content"),
        "Chat_EmptyStateTitle.Text": ("chat.empty_state_title", "Text"),
        "Chat_EmptyStateDesc.Text": ("chat.empty_state_desc", "Text"),
    }

    resw_header = """<?xml version="1.0" encoding="utf-8"?>
<root>
  <xsd:schema id="root" xmlns="" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:msdata="urn:schemas-microsoft-com:xml-msdata">
    <xsd:element name="root" msdata:IsDataSet="true">
      <xsd:complexType>
        <xsd:choice maxOccurs="unbounded">
          <xsd:element name="data">
            <xsd:complexType>
              <xsd:sequence>
                <xsd:element name="value" type="xsd:string" minOccurs="0" msdata:Ordinal="1" />
                <xsd:element name="comment" type="xsd:string" minOccurs="0" msdata:Ordinal="2" />
              </xsd:sequence>
              <xsd:attribute name="name" type="xsd:string" use="required" msdata:Ordinal="1" />
              <xsd:attribute name="type" type="xsd:string" msdata:Ordinal="3" />
              <xsd:attribute name="mimetype" type="xsd:string" msdata:Ordinal="4" />
              <xsd:attribute ref="xml:space" />
            </xsd:complexType>
          </xsd:element>
        </xsd:choice>
      </xsd:complexType>
    </xsd:element>
  </xsd:schema>
  <resheader name="resmimetype">
    <value>text/microsoft-resx</value>
  </resheader>
  <resheader name="version">
    <value>2.0</value>
  </resheader>
  <resheader name="reader">
    <value>Microsoft.Build.Tasks.ResourceHandling.RestrictedResXFileHandler, Microsoft.Build.Tasks.v4.0, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a</value>
  </resheader>
  <resheader name="writer">
    <value>Microsoft.Build.Tasks.ResourceHandling.RestrictedResXFileHandler, Microsoft.Build.Tasks.v4.0, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a</value>
  </resheader>
"""

    def write_resw(file_path: Path, is_tr: bool):
        file_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [resw_header]
        all_keys = sorted(pairs.keys())
        for k in all_keys:
            val = pairs[k][0 if is_tr else 1]
            escaped = saxutils.escape(val)
            safe_k = k.replace(".", "_")
            lines.append(f'  <data name="{safe_k}" xml:space="preserve">\n    <value>{escaped}</value>\n  </data>\n')

        for alias_key, (source_key, _) in aliases.items():
            if source_key in pairs:
                val = pairs[source_key][0 if is_tr else 1]
                escaped = saxutils.escape(val)
                lines.append(f'  <data name="{alias_key}" xml:space="preserve">\n    <value>{escaped}</value>\n  </data>\n')

        lines.append("</root>\n")
        file_path.write_text("".join(lines), encoding="utf-8")
        print(f"Written {file_path} with {len(all_keys) + len(aliases)} entries")

    tr_path = Path("apps/windows/Fetih.Desktop/Strings/tr-TR/Resources.resw")
    en_path = Path("apps/windows/Fetih.Desktop/Strings/en-US/Resources.resw")

    write_resw(tr_path, is_tr=True)
    write_resw(en_path, is_tr=False)

if __name__ == "__main__":
    generate_resw()
