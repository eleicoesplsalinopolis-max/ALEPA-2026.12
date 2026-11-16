import React from 'react';
import { FileCheck2, Lock, Mail, ShieldCheck, UserCheck, X } from 'lucide-react';
import { PageHeader, SectionCard } from './ui/CampusPrimitives';

export const PRIVACY_VERSION = '2026.1';

interface PrivacyViewProps {
  onBack?: () => void;
  onNavigateSettings?: () => void;
}

export function PrivacyContent() {
  return (
    <div className="space-y-4 text-xs sm:text-sm leading-relaxed text-slate-700 dark:text-slate-300">
      <div className="p-3.5 rounded-xl bg-emerald-50/80 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 flex items-start gap-2.5">
        <ShieldCheck className="w-5 h-5 text-[#146C43] dark:text-emerald-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <p className="font-bold text-[#0B3321] dark:text-emerald-200">
            Política de Privacidade e Termos de Uso · Versão {PRIVACY_VERSION}
          </p>
          <p className="text-xs text-slate-700 dark:text-slate-300">
            Este documento descreve como o <strong>Meu Campus ALEPA 2026</strong> trata seus dados pessoais em conformidade com a Lei Geral de Proteção de Dados (LGPD — Lei nº 13.709/2018).
          </p>
        </div>
      </div>

      <SectionCard
        title="1. Dados Coletados"
        subtitle="Informações estritamente necessárias ao funcionamento da plataforma"
      >
        <ul className="list-disc pl-5 space-y-1.5">
          <li>
            <strong>Dados cadastrais e de identificação:</strong> endereço de e-mail, nome de exibição, identificador de conta (UID), papel atribuído, cargo/edital selecionado e data e versão de aceite destes termos.
          </li>
          <li>
            <strong>Dados de estudo e desempenho:</strong> marcações de tópicos estudados, sessões de cronograma, resultados de simulados, anotações do caderno de erros, metas semanais, progresso de leitura/destaques em PDFs e progresso de mídia.
          </li>
          <li>
            <strong>Registros técnicos de acesso:</strong> identificadores de sessão e tipo de dispositivo usados para sincronização entre computador e celular.
          </li>
          <li>
            <strong>Acesso familiar compartilhado:</strong> quando convidado pelo administrador, registro de vínculo familiar (nome, e-mail e relação) para liberação da biblioteca compartilhada.
          </li>
        </ul>
      </SectionCard>

      <SectionCard
        title="2. Finalidade e Base Legal"
        subtitle="Por que e com qual fundamento tratamos os dados"
      >
        <ul className="list-disc pl-5 space-y-1.5">
          <li>
            <strong>Execução do serviço educacional (Art. 7º, V da LGPD):</strong> autenticar sua conta, organizar o plano de estudos para os Editais 001/2026 e 002/2026, calcular desempenho e sincronizar seu progresso entre dispositivos.
          </li>
          <li>
            <strong>Consentimento do titular (Art. 7º, I da LGPD):</strong> aceite expresso desta Política no cadastro/login e integrações opcionais acionadas diretamente por você (Google Drive, Planilhas, Apresentações, Google Calendar ou Gmail).
          </li>
          <li>
            <strong>Segurança e prevenção a abusos (Art. 7º, IX):</strong> controle de taxa de requisições, auditoria administrativa e proteção das regras de acesso ao banco de dados.
          </li>
        </ul>
      </SectionCard>

      <SectionCard
        title="3. Compartilhamento com Terceiros"
        subtitle="Serviços externos acionados pela plataforma"
      >
        <ul className="list-disc pl-5 space-y-1.5">
          <li>
            <strong>Google Firebase (Authentication, Firestore e Cloud Storage):</strong> infraestrutura de autenticação e armazenamento em nuvem dos dados da conta.
          </li>
          <li>
            <strong>Google Gemini API:</strong> processamento sob demanda apenas do texto, link ou PDF enviado explicitamente ao módulo Professor IA para geração de resumos.
          </li>
          <li>
            <strong>Spotify e YouTube (modo sem cookies quando aplicável):</strong> incorporação de players de aulas e podcasts mediante reprodução solicitada pelo usuário; o conector Spotify utiliza tokens restritos à sua sessão.
          </li>
        </ul>
      </SectionCard>

      <SectionCard
        title="4. Retenção e Segurança"
        subtitle="Prazo de guarda e medidas técnicas"
      >
        <ul className="list-disc pl-5 space-y-1.5">
          <li>
            <strong>Sessões de acesso:</strong> registros em <code>accessSessions</code> recebem prazo de expiração automática de 30 dias.
          </li>
          <li>
            <strong>Dados de estudo:</strong> mantidos enquanto sua conta estiver ativa ou até que você solicite a exclusão completa pelas Configurações.
          </li>
          <li>
            <strong>Isolamento de acesso:</strong> regras de segurança no servidor garantem que dados pessoais de progresso, simulados e anotações sejam acessíveis apenas ao próprio titular.
          </li>
        </ul>
      </SectionCard>

      <SectionCard
        title="5. Direitos do Titular (LGPD Art. 18)"
        subtitle="Autoatendimento disponível na sua conta"
      >
        <div className="space-y-2">
          <p>
            Você pode exercer a qualquer momento os direitos de confirmação da existência de tratamento, acesso, correção, portabilidade e eliminação dos seus dados:
          </p>
          <ul className="list-disc pl-5 space-y-1">
            <li>
              <strong>Exportação (Portabilidade):</strong> em <em>Configurações → Privacidade e LGPD</em>, clique em <strong>Exportar meus dados</strong> para baixar um arquivo JSON completo com seu perfil, histórico e sessões.
            </li>
            <li>
              <strong>Exclusão definitiva:</strong> na mesma seção, utilize a confirmação em duas etapas para apagar seus dados de perfil, subcoleções de estudo, sessões de acesso e conta de autenticação.
            </li>
          </ul>
        </div>
      </SectionCard>

      <SectionCard
        title="6. Controlador e Encarregado (DPO)"
        subtitle="Canal de contato para solicitações de privacidade"
      >
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-800/70 border border-slate-200 dark:border-slate-700 flex items-start gap-2.5">
            <UserCheck className="w-4 h-4 text-[#146C43] dark:text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <p className="font-bold text-slate-900 dark:text-slate-100">Controlador</p>
              <p className="mt-0.5 font-mono text-slate-700 dark:text-slate-300">{'{{CONTROLADOR}}'}</p>
            </div>
          </div>
          <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-800/70 border border-slate-200 dark:border-slate-700 flex items-start gap-2.5">
            <Mail className="w-4 h-4 text-[#146C43] dark:text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <p className="font-bold text-slate-900 dark:text-slate-100">Encarregado pelo Tratamento (DPO)</p>
              <p className="mt-0.5 font-mono text-slate-700 dark:text-slate-300">{'{{DPO_EMAIL}}'}</p>
            </div>
          </div>
        </div>
      </SectionCard>

      <SectionCard
        title="7. Termos de Uso"
        subtitle="Condições gerais de utilização da plataforma"
      >
        <ul className="list-disc pl-5 space-y-1.5">
          <li>
            A plataforma destina-se exclusivamente à preparação educacional individual ou familiar autorizada para o Concurso ALEPA 2026.
          </li>
          <li>
            Materiais públicos e fontes oficiais permanecem sob titularidade de seus respectivos autores e órgãos emissores; conteúdos enviados pelo usuário devem respeitar direitos autorais e legislação vigente.
          </li>
          <li>
            O descumprimento das regras de uso ou tentativas de acesso não autorizado sujeitam a conta à suspensão administrativa.
          </li>
        </ul>
      </SectionCard>
    </div>
  );
}

export function PrivacyView({ onBack, onNavigateSettings }: PrivacyViewProps) {
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="LGPD & Transparência"
        title="Política de Privacidade e Termos de Uso"
        subtitle="Consulte como seus dados de estudo são coletados, protegidos, exportados e excluídos."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {onNavigateSettings && (
              <button
                type="button"
                onClick={onNavigateSettings}
                className="min-h-[40px] px-3.5 py-2 rounded-xl bg-[#0B3321] text-white text-xs font-semibold inline-flex items-center gap-1.5"
              >
                <Lock className="w-3.5 h-3.5" />
                <span>Exportar ou Excluir Dados</span>
              </button>
            )}
            {onBack && (
              <button
                type="button"
                onClick={onBack}
                className="min-h-[40px] px-3.5 py-2 rounded-xl border border-slate-300 dark:border-slate-700 text-xs font-semibold"
              >
                Voltar
              </button>
            )}
          </div>
        }
      />
      <PrivacyContent />
    </div>
  );
}

export function PrivacyModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  if (!open) return null;
  return (
    <div
      role="presentation"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      className="fixed inset-0 z-50 bg-slate-950/60 backdrop-blur-xs flex items-center justify-center p-3 sm:p-6"
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Política de Privacidade e Termos de Uso"
        className="w-full max-w-3xl max-h-[88dvh] bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden"
      >
        <div className="px-4 sm:px-6 py-3.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-2">
            <FileCheck2 className="w-5 h-5 text-[#146C43] dark:text-emerald-400" />
            <h2 className="font-display text-base sm:text-lg font-bold text-slate-900 dark:text-slate-100">
              Política de Privacidade e Termos de Uso
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Fechar Política de Privacidade"
            className="min-w-[40px] min-h-[40px] rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 flex items-center justify-center"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-4 sm:p-6">
          <PrivacyContent />
        </div>
        <div className="px-4 sm:px-6 py-3 border-t border-slate-200 dark:border-slate-800 flex justify-end shrink-0">
          <button
            type="button"
            onClick={onClose}
            className="min-h-[40px] px-4 py-2 rounded-xl bg-[#0B3321] text-white text-xs font-semibold"
          >
            Entendi e Fechar
          </button>
        </div>
      </div>
    </div>
  );
}
