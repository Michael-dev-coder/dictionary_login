import pyttsx3


s = pyttsx3.init()


def text_to_speech(text):
    rate = s.getProperty('rate')
    s.setProperty('rate', 145)
    s.startLoop(False)
    s.say(text)
    s.iterate()
    s.endLoop()