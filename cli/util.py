import typer

def style_error(message: str):
    """
    Style an error message for cli.

    :param message: Error message.
    :return: Styled message.
    """
    return typer.style("Error: ", fg=typer.colors.RED, bold=True)+ \
                      typer.style(message, fg=typer.colors.RED)

def style_positive_response(message: str):
    """
    Style a positive response message for cli.

    :param message: Positive response message.
    :return: Styled message.
    """

    return typer.style(message, fg=typer.colors.BRIGHT_BLUE, bold=True)