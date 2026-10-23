package main

import (
	"fmt"
	"os"

	"charm.land/huh/v2"

	"github.com/heschaefer/envmem/internal/client"
)

// Ações de administração do modo interativo: membros (gestor, admin e
// superadmin), projetos (admin e superadmin) e usuários (superadmin). Como
// no resto do menu, esconder é conforto: o servidor confere cada rota, e
// as regras que dependem do alvo (o gestor não mexe em outro gestor) são
// conferidas no handler (decisão 5).

// Ações sobre um membro e ações globais do menu principal. Continuam a
// numeração de menuAction (interactive.go).
const (
	actMakeGestor menuAction = iota + 100
	actMakeDev
	actRemoveMember
	actMembers
	actOpenProject
	actCreateProject
	actDeleteProject
	actUsers
	actQuit
)

// memberActions devolve o que quem está logado (viewer) pode fazer com um
// membro, conforme o papel dele no projeto: só admin e superadmin nomeiam,
// rebaixam ou removem gestores; o gestor só mexe com desenvolvedores.
func memberActions(viewer, member string) []actionItem {
	var items []actionItem
	switch {
	case isAdmin(viewer) && member == "desenvolvedor":
		items = append(items, actionItem{"Tornar gestor", actMakeGestor})
	case isAdmin(viewer) && member == "gestor":
		items = append(items, actionItem{"Tornar desenvolvedor", actMakeDev})
	}
	if isAdmin(viewer) || (viewer == "gestor" && member == "desenvolvedor") {
		items = append(items, actionItem{"Remover do projeto", actRemoveMember})
	}
	return append(items, actionItem{"Voltar", actBack})
}

// globalActions devolve as ações do menu principal, abaixo dos projetos,
// conforme o papel global: admin e superadmin criam e removem projetos;
// só o superadmin administra usuários.
func globalActions(globalRole string) []actionItem {
	var items []actionItem
	if isAdmin(globalRole) {
		items = append(items,
			actionItem{"Criar projeto", actCreateProject},
			actionItem{"Remover projeto", actDeleteProject},
		)
	}
	if globalRole == "superadmin" {
		items = append(items, actionItem{"Usuários", actUsers})
	}
	return append(items, actionItem{"Sair", actQuit})
}

// membersMenu lista os membros do projeto e, para o escolhido, as ações
// permitidas; também adiciona membros. Fica no menu até o usuário voltar.
func membersMenu(c *client.Client, project, role string) error {
	for {
		ctx, cancel := apiContext()
		members, err := c.Members(ctx, project)
		cancel()
		if err != nil {
			return err
		}

		// -1 é Voltar, -2 é Adicionar; os outros apontam para a lista.
		options := make([]huh.Option[int], 0, len(members)+2)
		for i, m := range members {
			options = append(options, huh.NewOption(fmt.Sprintf("%s (%s)", m.Email, m.Role), i))
		}
		options = append(options, huh.NewOption("Adicionar membro", -2), huh.NewOption("Voltar", -1))
		choice := options[0].Value
		description := ""
		if len(members) == 0 {
			description = "O projeto ainda não tem membros"
		}
		err = huh.NewSelect[int]().Title("Membros de " + project).Description(description).Options(options...).Value(&choice).Run()
		if err != nil || choice == -1 {
			return err
		}

		if choice == -2 {
			err = addMember(c, project, role)
		} else {
			err = memberMenu(c, project, role, members[choice])
		}
		if err != nil {
			if isAbort(err) {
				return err
			}
			printError(err)
		}
	}
}

// addMember pede o e-mail e, para admin e superadmin, o papel; o gestor só
// adiciona desenvolvedores.
func addMember(c *client.Client, project, role string) error {
	var email string
	newRole := "desenvolvedor"
	fields := []huh.Field{
		huh.NewInput().Title("E-mail do usuário").Description("O usuário precisa existir (criado por um superadmin)").Value(&email),
	}
	if isAdmin(role) {
		fields = append(fields, huh.NewSelect[string]().Title("Papel no projeto").
			Options(huh.NewOption("Desenvolvedor", "desenvolvedor"), huh.NewOption("Gestor", "gestor")).
			Value(&newRole))
	}
	if err := huh.NewForm(huh.NewGroup(fields...)).Run(); err != nil {
		return err
	}
	ctx, cancel := apiContext()
	defer cancel()
	m, err := c.SetMember(ctx, project, email, newRole)
	if err != nil {
		return err
	}
	fmt.Printf("%s é %s no projeto %s\n", m.Email, m.Role, project)
	return nil
}

// memberMenu mostra as ações sobre um membro.
func memberMenu(c *client.Client, project, role string, m client.Member) error {
	items := memberActions(role, m.Role)
	if len(items) == 1 { // só Voltar
		fmt.Fprintln(os.Stderr, "só admin e superadmin mexem em gestores")
		return nil
	}
	options := make([]huh.Option[menuAction], 0, len(items))
	for _, it := range items {
		options = append(options, huh.NewOption(it.label, it.action))
	}
	action := items[0].action
	if err := huh.NewSelect[menuAction]().Title(fmt.Sprintf("%s (%s)", m.Email, m.Role)).Options(options...).Value(&action).Run(); err != nil {
		return err
	}

	ctx, cancel := apiContext()
	defer cancel()
	switch action {
	case actMakeGestor, actMakeDev:
		newRole := "gestor"
		if action == actMakeDev {
			newRole = "desenvolvedor"
		}
		updated, err := c.SetMember(ctx, project, m.Email, newRole)
		if err != nil {
			return err
		}
		fmt.Printf("%s é %s no projeto %s\n", updated.Email, updated.Role, project)
	case actRemoveMember:
		// Sem confirmação: adicionar de novo desfaz.
		if err := c.RemoveMember(ctx, project, m.UserID); err != nil {
			return err
		}
		fmt.Printf("%s não é mais membro do projeto %s\n", m.Email, project)
	}
	return nil
}

// createProject pede o nome e cria o projeto. Ele nasce sem gestor
// (decisão 44): quem cria nomeia um em "Membros do projeto".
func createProject(c *client.Client) error {
	var name string
	err := huh.NewInput().
		Title("Nome do projeto").
		Description("Minúsculas, dígitos e hífen, como app-homo. Cada ambiente é um projeto.").
		Value(&name).
		Run()
	if err != nil {
		return err
	}
	ctx, cancel := apiContext()
	defer cancel()
	p, err := c.CreateProject(ctx, name)
	if err != nil {
		return err
	}
	fmt.Printf("projeto %s criado; nomeie um gestor em Membros do projeto\n", p.Name)
	return nil
}

// deleteProject remove um projeto escolhido na lista, depois de
// confirmar. O servidor só remove projetos sem variáveis (409).
func deleteProject(c *client.Client, projects []client.Project) error {
	if len(projects) == 0 {
		fmt.Fprintln(os.Stderr, "não há projetos")
		return nil
	}
	options := make([]huh.Option[string], 0, len(projects)+1)
	for _, p := range projects {
		options = append(options, huh.NewOption(p.Name, p.Name))
	}
	options = append(options, huh.NewOption("Voltar", ""))
	name := options[0].Value
	if err := huh.NewSelect[string]().Title("Remover qual projeto?").Options(options...).Value(&name).Run(); err != nil || name == "" {
		return err
	}
	ok := false
	err := huh.NewConfirm().
		Title(fmt.Sprintf("Remover o projeto %s?", name)).
		Description("Só um projeto sem variáveis pode ser removido.").
		Affirmative("Remover").Negative("Cancelar").
		Value(&ok).Run()
	if err != nil {
		return err
	}
	if !ok {
		return errCanceled
	}
	ctx, cancel := apiContext()
	defer cancel()
	if err := c.DeleteProject(ctx, name); err != nil {
		return err
	}
	fmt.Printf("projeto %s removido\n", name)
	return nil
}

// usersMenu lista os usuários e, para o escolhido, oferece redefinir a
// senha e remover; também cria usuários. Só o superadmin chega aqui.
func usersMenu(c *client.Client) error {
	for {
		ctx, cancel := apiContext()
		users, err := c.Users(ctx)
		cancel()
		if err != nil {
			return err
		}

		// -1 é Voltar, -2 é Criar; os outros apontam para a lista.
		options := make([]huh.Option[int], 0, len(users)+2)
		for i, u := range users {
			label := u.Email + " (" + displayRole(u.GlobalRole) + ")"
			if u.TempPassword {
				label += ", senha temporária"
			}
			options = append(options, huh.NewOption(label, i))
		}
		options = append(options, huh.NewOption("Criar usuário", -2), huh.NewOption("Voltar", -1))
		choice := options[0].Value
		if err := huh.NewSelect[int]().Title("Usuários").Options(options...).Value(&choice).Run(); err != nil || choice == -1 {
			return err
		}

		if choice == -2 {
			err = createUserForm(c)
		} else {
			err = userMenu(c, users[choice])
		}
		if err != nil {
			if isAbort(err) {
				return err
			}
			if isCanceled(err) {
				fmt.Fprintln(os.Stderr, "cancelado")
				continue
			}
			printError(err)
		}
	}
}

// displayRole mostra o papel global; vazio é usuário comum, que vira
// gestor ou desenvolvedor por projeto.
func displayRole(globalRole string) string {
	if globalRole == "" {
		return "usuário"
	}
	return globalRole
}

// createUserForm pede e-mail, papel global e a senha temporária (duas
// vezes, mascarada), e cria o usuário (decisão 43).
func createUserForm(c *client.Client) error {
	var email, role string
	err := huh.NewForm(huh.NewGroup(
		huh.NewInput().Title("E-mail").Value(&email),
		huh.NewSelect[string]().Title("Papel global").
			Description("Gestor e desenvolvedor são papéis por projeto, dados em Membros do projeto").
			Options(
				huh.NewOption("Usuário comum", ""),
				huh.NewOption("Admin", "admin"),
				huh.NewOption("Superadmin", "superadmin"),
			).
			Value(&role),
	)).Run()
	if err != nil {
		return err
	}
	password, err := readTempPasswordForm()
	if err != nil {
		return err
	}
	ctx, cancel := apiContext()
	defer cancel()
	return createUser(ctx, c, email, role, password)
}

// userMenu oferece redefinir a senha e remover o usuário.
func userMenu(c *client.Client, u client.User) error {
	const reset, remove, back = 1, 2, 0
	action := reset
	err := huh.NewSelect[int]().
		Title(u.Email+" ("+displayRole(u.GlobalRole)+")").
		Options(
			huh.NewOption("Redefinir a senha (nova senha temporária)", reset),
			huh.NewOption("Remover", remove),
			huh.NewOption("Voltar", back),
		).
		Value(&action).Run()
	if err != nil || action == back {
		return err
	}

	switch action {
	case reset:
		password, err := readTempPasswordForm()
		if err != nil {
			return err
		}
		ctx, cancel := apiContext()
		defer cancel()
		return resetPassword(ctx, c, u, password)
	case remove:
		// Como no "envmem users rm": sem lixeira, então confirma antes.
		ok := false
		err := huh.NewConfirm().
			Title(fmt.Sprintf("Remover %s?", u.Email)).
			Description("As sessões e os acessos a projetos são apagados, sem como desfazer.").
			Affirmative("Remover").Negative("Cancelar").
			Value(&ok).Run()
		if err != nil {
			return err
		}
		if !ok {
			return errCanceled
		}
		ctx, cancel := apiContext()
		defer cancel()
		return deleteUser(ctx, c, u)
	}
	return nil
}

// readTempPasswordForm pede a senha temporária duas vezes, mascarada.
func readTempPasswordForm() (string, error) {
	return readTwiceForm("Senha temporária", "De 12 a 128 caracteres; vale 72 horas e é trocada no primeiro login",
		"Repita a senha temporária", "as senhas não conferem")
}
