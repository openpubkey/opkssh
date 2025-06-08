#!/usr/bin/env bash

SCRIPT_FILE="${1:-install-linux.sh}"

extract_usage_options() {
    awk '
        BEGIN { in_block=0 }

        /^# ===+/ { in_block = !in_block; next }

        in_block && /^# +--/ {
            if (option && desc) {
                gsub(/</, "\\&lt;", desc)
                gsub(/>/, "\\&gt;", desc)
                gsub(/^[[:space:]]+/, "", desc)
                printf "  `%s`\n\n  %s\n\n", option, desc
            }
            option = $2  # Preserve the -- prefix
            desc = ""
            next
        }

        in_block && /^# +/ {
            line = substr($0, 3)
            if (option) {
                if (desc) desc = desc " " line
                else desc = line
            }
        }

        END {
            if (option && desc) {
                gsub(/^[[:space:]]+/, "", desc)
                printf "- `%s`: %s\n\n", option, desc
            }
        }
        ' "$SCRIPT_FILE"
}

extract_global_variables() {
    grep -E '^[[:space:]]*[A-Z_]+=.*\$\{OPKSSH_[A-Z_]+:-[^}]+\}' "$SCRIPT_FILE" | while IFS= read -r line; do
        # Get variable name before '='
        varname=$(echo "$line" | sed -E 's/^\s*([A-Z_]+)=.*/\1/')
        # Extract default value inside ${...:-default}
        default=$(echo "$line" | sed -nE 's/.*\$\{OPKSSH_[A-Z_]+:-([^}]+)\}.*/\1/p')
        # Extract referenced environment variable name
        env_var=$(echo "$line" | sed -nE 's/.*\$\{(OPKSSH_[A-Z_]+):-[^}]+\}.*/\1/p')
        echo "| **$varname** | \`$default\` | $env_var |"
    done
}

format_doc_block() {
    local doc="$1"
    local in_args=0
    local in_returns=0
    local in_outputs=0
    local in_example=0

    while IFS= read -r line; do
        case "$line" in
            Arguments:*)
                echo "**Arguments:**"
                in_args=1; in_returns=0; in_outputs=0; in_example=0
                ;;
            Returns:*)
                echo; echo "**Returns:**"
                in_args=0; in_returns=1; in_outputs=0; in_example=0
                ;;
            Outputs:*)
                echo; echo "**Outputs:**"
                in_args=0; in_returns=0; in_outputs=1; in_example=0
                ;;
            Example:*)
                echo; echo "**Example:**"; echo '```bash'
                in_args=0; in_returns=0; in_outputs=0; in_example=1
                ;;
            shellcheck*)
                ;;
            "")
                if [[ $in_example -eq 1 ]]; then
                    echo '```';
                fi
                in_args=0; in_returns=0; in_outputs=0; in_example=0
                echo
                ;;
            *)
                if [[ $in_args -eq 1 || $in_returns -eq 1 || $in_outputs -eq 1 ]]; then
                    echo "- ${line}"
                elif [[ $in_example -eq 1 ]]; then
                    echo "$line"
                else
                    echo "$line"
                fi
                ;;
        esac
    done <<< "$doc"
}

# main

echo "## Command-Line Arguments"
echo
echo "Usage: \`$SCRIPT_FILE [OPTIONS]\`"
echo
echo "Options:"
echo
extract_usage_options

echo "## Environment Variables"
echo
echo "| Variable name | Default value | System env override |"
echo "|---------------|---------------|---------------------|"
extract_global_variables

echo
echo "# Script Function Documentation"
echo
while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^#[[:space:]]?(.*)$ ]]; then
        doc_block+="${BASH_REMATCH[1]}"$'\n'
        in_doc=1
    elif [[ $in_doc -eq 1 && "$line" =~ ^([a-zA-Z_][a-zA-Z0-9_]*)\(\)[[:space:]]*\{ ]]; then
        function_name="${BASH_REMATCH[1]}"
        echo "## \`$function_name\`"
        echo
        format_doc_block "$doc_block"
        echo
        doc_block=""
        in_doc=0
    else
        doc_block=""
        in_doc=0
    fi
done < "$SCRIPT_FILE"
