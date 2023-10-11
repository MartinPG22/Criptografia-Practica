def sign_in():
    print("Sign In button clicked")

def log_in():
    print("Log In button clicked")
def main():
    ventana = tk.Tk()
    ventana.title("Ejemplo de Sign In y Log In")

    # Crear un botón "Sign In"
    btn_sign_in = tk.Button(ventana, text="Sign In", command=sign_in)
    btn_sign_in.pack(pady=10)

    # Crear un botón "Log In"
    btn_log_in = tk.Button(ventana, text="Log In", command=log_in)
    btn_log_in.pack(pady=10)

    # Iniciar el bucle principal de la ventana
    ventana.mainloop()

if __name__ == "__main__":
    main()