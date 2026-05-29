"""JSON schemas for all computer_use tool actions.

The tool presents a single ``computer_use`` function to the model.
The ``action`` field selects the operation; each action has its own
required/optional parameters documented here.
"""

COMPUTER_USE_SCHEMA = {
    "name": "computer_use",
    "description": (
        "Control the desktop: take screenshots, move/click the mouse, "
        "type text, press keys, and scroll. Works cross-platform on "
        "Windows, macOS, and Linux. "
        "FAILSAFE: move the mouse to the upper-left corner (0,0) to abort."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "screenshot",
                    "click",
                    "double_click",
                    "right_click",
                    "middle_click",
                    "move_mouse",
                    "type",
                    "key",
                    "scroll",
                    "get_screen_size",
                    "get_mouse_position",
                    "drag",
                    "wait",
                ],
                "description": "The desktop action to perform.",
            },
            "coordinate": {
                "type": "array",
                "items": {"type": "integer"},
                "minItems": 2,
                "maxItems": 2,
                "description": "[x, y] pixel coordinates for click/move actions.",
            },
            "text": {
                "type": "string",
                "description": "Text to type (for 'type' action).",
            },
            "keys": {
                "type": "string",
                "description": (
                    "Key combination to press, e.g. 'ctrl+c', 'alt+f4', 'enter'. "
                    "Separate keys with '+'. Use key names: ctrl, alt, shift, "
                    "win/cmd, enter, escape, tab, backspace, delete, up, down, "
                    "left, right, f1-f12, etc."
                ),
            },
            "direction": {
                "type": "string",
                "enum": ["up", "down", "left", "right"],
                "description": "Scroll direction.",
            },
            "amount": {
                "type": "integer",
                "description": "Number of scroll clicks (default: 3).",
                "default": 3,
            },
            "from_coordinate": {
                "type": "array",
                "items": {"type": "integer"},
                "minItems": 2,
                "maxItems": 2,
                "description": "Start [x, y] for drag action.",
            },
            "to_coordinate": {
                "type": "array",
                "items": {"type": "integer"},
                "minItems": 2,
                "maxItems": 2,
                "description": "End [x, y] for drag action.",
            },
            "duration": {
                "type": "number",
                "description": "Duration in seconds for wait or smooth mouse move.",
            },
            "interval": {
                "type": "number",
                "description": "Interval between keystrokes in seconds (default: 0.0).",
            },
        },
        "required": ["action"],
    },
}
