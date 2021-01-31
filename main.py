from kivy.app import App
from kivy.uix.scatter import Scatter
from kivy.uix.label import Label
from kivy.uix.floatlayout import FloatLayout

class VCStegGuiApp(App):

    def build(self):
        self.icon= 'icon.png'
        f = FloatLayout()
        s = Scatter()
        l = Label(text="Blackhorse VC Steg GUI",
                    font_size = 150)
        
        f.add_widget(s)
        s.add_widget(l)
        return f

if __name__ == "__main__":
    # execute only if run as a script
    VCStegGuiApp().run()