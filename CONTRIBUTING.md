# Contribuindo

## Fluxo

1. Trabalhe em uma branch curta baseada em `main`.
2. Mantenha o escopo read-only e atualize a matriz de permissões quando um
   novo endpoint for adicionado.
3. Adicione ou ajuste testes para cada mudança de contrato, scoring ou coleta.
4. Execute localmente:

   ```bash
   python -m py_compile src/*.py
   python -m unittest discover -s tests -v
   python src/generate_report.py --data mock/assessment.json --output /tmp/assessment.html
   ```

5. Faça commits pequenos e descritivos. Nunca inclua saídas de tenant no Git.

## Critérios de aceite

- falhas de permissão/licença continuam classificadas sem interromper o
  assessment completo;
- toda evidência tem origem e limitação identificáveis;
- nenhum teste ou coletor permite mutação do tenant;
- o relatório demo continua autocontido e abre offline.

