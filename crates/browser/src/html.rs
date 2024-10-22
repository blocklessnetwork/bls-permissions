pub struct Html;

impl Html {
    #[inline(always)]
    pub fn span_color(color: &str, message: &str) -> String {
        format!("<span style='color:{color}'>{message}</span>")
    }

    pub fn bold(message: &str) -> String {
        format!("<b>{message}</b>")
    }

    pub fn color_with_underline(color: &str, msg: &str) -> String {
        format!("<span style='text-decoration: underline;background-color:{color}'>{msg}</span>")
    }

    pub fn italic(msg: &str) -> String {
        format!("<span style='font-style: italic'>{msg}</span>")
    }
    
}